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
  OWASP Top 10) y parte 2 (JWT/OAuth 2.0, validación de entradas y rate
  limiting en C, filosofía suckless).

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
- SHA-256 y HMAC-SHA-256 propios (sin OpenSSL);
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
