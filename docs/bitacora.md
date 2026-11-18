# Bitácora de trabajo — Actividad 4

Registro cronológico del procedimiento, decisiones y problemas encontrados.
Los commits se hicieron sin firma GPG (`-c commit.gpgsign=false`) porque el
agente no tiene acceso a la clave del usuario.

## 0. Revisión inicial

- El repositorio contenía la plantilla de LaTeX, `metadata.yaml`,
  `defaults.yaml`, `template.latex`, `header.tex`, `Makefile` y
  `instrucciones.txt`.
- `README.md` es el documento que se compila a PDF (`homework.md` es un
  symlink a `README.md`). El `Makefile` usa `pandoc` + `xelatex`.
- Instrucciones relevantes: parte 1 (DVWA + ZAP + tres vulnerabilidades del
  OWASP Top 10), parte 2 (JWT/OAuth 2.0, validación de entradas y rate
  limiting en C, filosofía suckless), parte 3 (pfSense/Snort) y parte 4
  (matriz de riesgos 5×5).

## 1. Primer intento con Docker (descartado)

Se intentó usar las imágenes `vulnerables/web-dvwa` y
`ghcr.io/zaproxy/zaproxy:stable`. La descarga funcionó, pero el motor Docker
del equipo no pudo crear contenedores:

```text
OCI runtime create failed: ... bpf_prog_query(BPF_CGROUP_DEVICE) failed:
bpf: function not implemented
```

El kernel del entorno no soporta la configuración de cgroups que necesita
`runc`; el problema no era de la aplicación. También se comprobó que el
sistema es Artix y que instalar MariaDB con `pacman` requería actualizar
OpenSSL y rompía dependencias del sistema.

**Decisión:** no usar Docker ni `sudo`/`doas`. Se adoptó un *flake* de Nix,
que permite tener PHP, MariaDB y ZAP con versiones fijas, en el espacio del
usuario y sin tocar el sistema.

## 2. Flake de Nix

Se creó `flake.nix` con:

- `php` (incluye `mysqli` y `pdo_mysql`),
- `mariadb` (servidor y cliente),
- `zap` (OWASP ZAP 2.17.0),
- `curl`, `jq`, `python3`, `gcc`, `gnu make`, `git`, `nmap`, `openssl`.

`nix flake lock` fijó nixpkgs en el commit
`d5cc6833999746cffdfe0598f7bc801a57b887a9` (2026-11-13). El *shell*
exporta `A4_ROOT` y `A4_LAB`.

## 3. Laboratorio DVWA

Se escribieron:

- `parte1/scripts/lab-up.sh`: descarga DVWA 2.5, inicializa MariaDB en
  `.lab/mysql` (socket y puerto 3307), crea la base/usuario, arranca el
  servidor embebido de PHP en `127.0.0.1:8081` y ejecuta la inicialización.
- `parte1/scripts/dvwa_init.py`: flujo con cookies y tokens CSRF:
  1. `GET /setup.php` y `POST create_db` con `user_token`;
  2. `GET /login.php`, extrae `user_token`, `POST admin/password`;
  3. `GET /security.php`, `POST security=low`;
  4. comprueba que `/vulnerabilities/sqli/?id=1` devuelve `First name`.
- `parte1/scripts/lab-down.sh`: apaga PHP y MariaDB por PID/socket, sin
  servicios del sistema.

Resultado: DVWA 2.5 operativa con seguridad `low` y sesión guardada en
`.lab/dvwa-session.env` (ignorado por Git).

## 4. OWASP ZAP

El primer intento de ZAP falló porque el paquete de Nix trae
`config.xml` en solo lectura y ZAP intenta reescribirlo:

```text
java.io.FileNotFoundException: .../.lab/zap/home/config.xml (Permission denied)
```

**Solución:** no usar `-dir`; se aisló `HOME` en `.lab/zap/home` para que el
wrapper de Nix cree allí un `config.xml` escribible. También se creó un plan
de automatización (`parte1/zap/plan.yaml`) con:

- contexto `dvwa` sobre `http://127.0.0.1:8081`,
- autenticación `manual` + variables `ZAP_AUTH_HEADER*` con la cookie de
  sesión (evita depender del token CSRF del login),
- job `requestor` para sembrar endpoints AJAX,
- `spider`, `passiveScan-wait`, `activeScan` y dos informes
  (`traditional-html` y `traditional-json`),
- exclusiones de `setup.php`, `logout.php` y `phpinfo.php`.

El escaneo se ejecutó en localhost contra una aplicación deliberadamente
vulnerable.

### Problemas del primer escaneo y ajustes

- El *spider* generó un espacio de URLs sin límite: el servidor embebido de
  PHP resolvía rutas como `/var/www/html/DVWA/vulnerabilities/csrf/...` con
  `200`, de modo que el árbol crecía de forma combinatoria. Se acotaron
  `includePaths` a `/`, `index.php` y `vulnerabilities/<módulo>/`, y se
  añadieron `excludePaths` para `var/www`, `../` y `mydir`.
- Un `activeScan` global tardaba demasiado. Se sustituyó por tres escaneos
  dirigidos a los módulos del alcance.
- El primer intento de escaneo dirigido apuntaba solo a la ruta
  (`/vulnerabilities/sqli/`), sin cadena de consulta, por lo que ZAP no tenía
  parámetros que inyectar. Se pasó la URL completa
  (`.../sqli/?id=1&Submit=Submit`, `.../xss_r/?name=test`).
- Los informes se generaban junto al plan (`parte1/zap/`) porque ZAP resuelve
  `reportDir` respecto al archivo de automatización. Se cambió a
  `../evidence`.
- Se usó `-newsession` en cada ejecución para no arrastrar el árbol de sitios
  de escaneos anteriores.

## 5. Evidencia manual

`parte1/scripts/capture-evidence.sh` reproduce los tres hallazgos y guarda
las respuestas en `parte1/evidence/`:

1. **SQLi**: `id=1' UNION SELECT user, password FROM users -- -` devuelve
   usuarios y hashes MD5.
2. **XSS reflejado**: `name=<script>alert(document.cookie)</script>` se
   refleja sin codificar y la respuesta envía `X-XSS-Protection: 0`.
3. **Broken Access Control**: `GET
   /vulnerabilities/authbypass/get_user_data.php` sin cookie devuelve
   `200 OK` con todos los usuarios; el código de
   `change_user_details.php` confirma que tampoco exige sesión ni rol.

## 6. Parte 2: API en C

Se implementó `parte2/api.c` (un solo archivo, libc/POSIX):

- servidor HTTP/1.1 mínimo con `socket`/`accept`/`recv`/`send`;
- inicialmente SHA-256 y HMAC-SHA-256 propios; después se sustituyeron por
  `EVP_Q_mac` de OpenSSL (ver §8);
- JWT HS256: emisión, decodificación base64url, verificación de firma,
  `alg`, `iss`, `aud`, `exp`, `iat`, `jti` y vida máxima;
- OAuth 2.0 `client_credentials` en `/oauth/token` con scopes `read` y
  `transfer`;
- validación de JSON plana y estricta (sin duplicados, sin UTF-8 no ASCII,
  sin floats/booleanos/null, sin campos extra);
- reglas de `account` (`^[A-Z]{3}-[0-9]{4}$`) y `amount` (1..1 000 000);
- rate limiting de 100 req/min por IP y por `sub`, con `429` +
  `Retry-After` y reinicio de ventana;
- hardening de compilación (`PIE`, `RELRO`, `FORTIFY_SOURCE`,
  `-fstack-protector-strong`, `-Werror`).

### Problemas encontrados y corregidos

- El primer `make` falló por `_GNU_SOURCE` duplicado y variables sin usar;
  se limpiaron las declaraciones.
- La decodificación base64url reutilizaba una variable de longitud y escribía
  el terminador con el tamaño equivocado; se separaron
  `hlen_dec`/`plen_dec`/`slen_dec`.
- El `429` del rate limiting no incluía `Retry-After` en dos rutas; se
  unificó la respuesta con la cabecera.
- Un cuerpo de 2000 bytes provocaba `RST` porque el servidor cerraba sin
  drenar; se añadió un drenaje acotado antes de responder `413`.
- Faltaban credenciales OAuth: se devolvía `401 invalid_client`; ahora
  `400 invalid_request` si faltan y `401` solo si son incorrectas.
- El `Content-Type` se comparaba con una longitud fija; se sustituyó por
  `ctype_is()` que acepta parámetros como `charset`.

### Pruebas

`parte2/tests/test_api.py` (solo biblioteca estándar) ejecuta **51 casos**:
OAuth, JWT, firma/alg/exp/iss/aud/scope, SQLi, XSS, command injection,
path traversal, JSON malformado, tipos incorrectos, tamaños, content-type,
404, 100 req/min, 429 + `Retry-After` y reinicio de ventana.

Resultado final: **51/51 correctas** (`parte2/evidence/test-results.txt`).

## 7. Documentación y compilación

- `parte1/README.md`: metodología, plantilla de riesgo y tres hallazgos.
- `parte2/README.md`: diseño, endpoints, reglas, pruebas y límites.
- `parte2/postman_collection.json`: colección lista para importar.
- `README.md`: informe integrado que se compila con `make`.

### Capturas del informe

Las seis figuras de `README.md` se generan con Selenium y Chromium desde el
laboratorio real; no son montajes:

```sh
nix develop .#screenshots -c python3 scripts/capture-screenshots.py
```

El *script* inicia sesión en DVWA, reproduce la inyección SQL y el XSS,
consulta `get_user_data.php` sin cookie, abre el informe HTML de ZAP y, para
la parte 2, arranca `parte2/api` en un puerto efímero y transcribe el flujo
real (token, perfil, transferencia, inyección rechazada y `429`). Las salidas
se guardan en `docs/screenshots/01-sqli.png` … `06-pruebas-api.png`.

Detalles de implementación que costaron tiempo:

- Chromium necesita `--no-sandbox` en este entorno y `chromedriver` debe
  coincidir con su versión (157).
- El visor JSON de Chrome no envuelve la línea; hay que dar estilo al `body`
  y recortar el margen blanco con Pillow.
- `wait_text` debe tolerar `StaleElementReferenceException`: DVWA recarga la
  página al cambiar de nivel de seguridad.
- El informe de ZAP no contiene el texto «ZAP Report»; la espera usa
  «Summary of Alerts».

### Compilación del PDF

`make` usa pandoc + xelatex y genera `homework.pdf` con las figuras
integradas. El PDF no se versiona (`homework*` en `.gitignore`); se regenera
con `make`.

## 8. Migración del HMAC a OpenSSL

El usuario aclaró que *dependencias mínimas* no significa *sin
dependencias*. Se eliminaron ~160 líneas de SHA-256/HMAC caseros de
`parte2/api.c` y se sustituyeron por una envoltura delgada alrededor de
`EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", ...)`. `parte2/Makefile` enlaza
ahora `-lcrypto` y el comentario del build refleja la dependencia. El
binario sigue compilando con `-Werror` y las **51/51** pruebas siguen
pasando; se regeneró `parte2/evidence/test-results.txt`.

**Decisión:** mantener una sola dependencia externa, pero que sea una
biblioteca criptográfica auditada. Los versos del informe que decían «sin
dependencias externas» se actualizaron a «OpenSSL como única dependencia».

## 9. Parte 3: pfSense, Snort y filtrado DNS

### 9.1 Arranque del laboratorio

- Se descargó `pfSense-CE-memstick-serial-2.7.2-RELEASE-amd64.img.gz` y se
  verificó el SHA-256 publicado por Netgate. El primer intento de verificar
  falló porque el archivo `.sha256` referencia el nombre completo y el
  descargado tenía otro nombre; se renombraron ambos y la suma coincidió.
- Se descargó `alpine-virt-3.20.3-x86_64.iso` para las dos sondas.
- El instalador de pfSense se automatizó primero con `pexpect`, pero el
  menú `newt` dibujaba con códigos de terminal que hacían frágil la
  coincidencia de texto. Se abandonó ese enfoque y se usó `tmux` como
  terminal interactiva: `tmux send-keys` y `tmux capture-pane` permiten
  conducir el instalador de forma visible y repetible.
- El primer `qemu-system-x86_64` con `-drive ...,bootindex=0` falló porque el
  formato `raw` no admite `bootindex`; se pasó a `-drive if=none` +
  `-device virtio-blk-pci,drive=...,bootindex=N`.
- Se instaló pfSense en `pfSense.qcow2` de 8 GB, se asignaron `vtnet0`…
  `vtnet3` a WAN/LAN/OPT1/OPT2 y se fijaron OPT1=`192.168.10.1/24` y
  OPT2=`192.168.20.1/24` desde el menú de consola.
- La GUI no respondía en `8443` porque el `hostfwd` apuntaba a una IP de
  gestión inexistente; se cambió a
  `hostfwd=tcp:127.0.0.1:8443-192.168.1.1:443` y tras reiniciar funcionó.

### 9.2 Paquetes y GUI

- `nixpkgs.snort` no enlaza en este sistema (`appid_log` sin definir), así
  que no se añadió al *flake*. Se instalaron Snort y pfBlockerNG desde el
  propio pfSense con `pkg install`: `pfSense-pkg-snort-4.1.6_17`,
  `pfSense-pkg-pfBlockerNG-devel-3.2.0_20` y, como dependencias, Snort
  2.9.20 y nmap 7.94.
- Se añadió `devShells.parte3` al flake con `qemu`, `pexpect`, `pyte`,
  `nmap`, `curl`, `jq` y `openssl`. La GUI se automatizó con Selenium desde
  `devShells.screenshots`.
- Los campos del login son `usernamefld`/`passwordfld` (no `username`).
- El botón *Apply Changes* no es un `input` ni un enlace: es
  `<button type="submit" name="apply" value="Apply Changes">`. El localizador
  que funciona es `button[name="apply"]`.
- En el editor de reglas, el puerto HTTP se selecciona por valor `80` en
  `dstbeginport`; no existe la opción `other` que se usó en el primer
  intento.
- En la pestaña de reglas de Snort, el guardado es
  `button#save`, no un `input[type=submit]`.

### 9.3 Reglas, Snort y DNS

- Se crearon los alias `VLAN_INTERNA` y `VLAN_NO_CONFIABLE` y tres reglas en
  OPT1: pass HTTP, pass DNS al propio firewall y block al resto de la VLAN
  interna, todas con log. Se aplicaron desde la GUI.
- La regla personalizada de Snort (SID `1000001`) detecta 15 SYN en 5 s
  desde el mismo origen. Se guardó en `custom.rules` de la interfaz OPT1 y
  Snort se arrancó con `snort_vtnet2_start`.
- *Block Offenders* está activado, pero la *pass list* por defecto incluye
  las redes locales, por lo que el atacante del laboratorio no fue añadido a
  la tabla de bloqueos; la validación es de detección, no de bloqueo IPS.
- El filtrado se implementó con `local-zone ... always_nxdomain` en las
  opciones personalizadas de Unbound. Antes se publicó un `local-data` de
  prueba y se verificó que `phishing.test` resolvía; después devuelve
  NXDOMAIN. El botón *Display Custom Options* (`btnadvcustom`) debe
  pulsarse antes de escribir en `custom_options`.

### 9.4 Sondas y validación

- Alpine arranca por serial (`ttyS0`) y permite entrar como `root` sin
  contraseña. El ISO solo trae sus propios `apks`, así que `apk add nmap`
  falló hasta que se añadieron los repositorios `v3.20/main` y
  `v3.20/community`. La sonda atacante necesitó una segunda NIC en user-mode
  para instalar el paquete.
- El objetivo no incluye `httpd`; se improvisó un servidor HTTP con un bucle
  de `nc -l -p 80` que devuelve una respuesta fija.
- Se añadió la ruta `192.168.20.0/24 vía 192.168.10.1` en el atacante. Sin
  ella, el tráfico salía por la NIC de Internet.
- `nmap -Pn -sS -T4 -p 1-200 192.168.20.10` devolvió 1 puerto abierto (80) y
  199 filtrados; `wget` obtuvo el texto del servidor interno; `nslookup`
  devolvió NXDOMAIN para los dominios bloqueados.
- La bitácora del firewall mostró los SYN bloqueados y el SYN permitido; la
  pestaña de alertas de Snort mostró `1:1000001`. Se capturaron las pantallas
  `07`…`12` y se renderizó la consola del atacante como `13-ataque-nmap.png`.
- Todo el procedimiento quedó en `parte3/README.md`, `setup-gui.py`, los
  scripts de arranque y los archivos de configuración/evidencia.

## 10. Parte 4: matriz de riesgos

Se construyeron las escalas de probabilidad e impacto (1–5), la matriz 5×5 y
doce riesgos identificados (R1–R12) que cubren las tres partes anteriores.
Se priorizaron con bandas de riesgo de cinco niveles y se propuso una
mitigación concreta para cada uno, indicando cuál ya estaba implementado y
cuál sigue pendiente. El plan de remediación se organizó en P0–P3; los
riesgos críticos son la inyección SQL, el control de acceso roto y el acceso
no autorizado a la VLAN interna.
