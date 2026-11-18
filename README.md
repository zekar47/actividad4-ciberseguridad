---
compile: true
---

# Resumen

Esta actividad cubre dos frentes de la seguridad de aplicaciones: el análisis
de vulnerabilidades web y el endurecimiento de una API. En la **parte 1** se
desplegó DVWA 2.5 en un laboratorio local, se escaneó con OWASP ZAP 2.17 y se
validaron manualmente tres fallos del OWASP Top 10: inyección SQL, XSS
reflejado y control de acceso roto. Cada hallazgo se documentó con su vector,
impacto, probabilidad, evidencia y mitigación. En la **parte 2** se implementó
una API HTTP en C11, sin dependencias externas, con OAuth 2.0 (*client
credentials*), JWT HS256, validación estricta de entradas y *rate limiting*
de 100 solicitudes por minuto. La implementación se probó con 51 casos
automatizados, todos correctos.

# Introducción

La superficie de ataque de una aplicación moderna incluye tanto el navegador
como la API que consume. Los errores de inyección y de autorización siguen
ocupando los primeros lugares del OWASP Top 10, mientras que las APIs
necesitan mecanismos explícitos de autenticación, autorización, validación y
límites de uso. Este trabajo aborda ambos lados:

- **Parte 1:** identificar y explotar vulnerabilidades reales en una
  aplicación deliberadamente vulnerable (DVWA), usando una herramienta
  estándar de la industria (OWASP ZAP) y validación manual.
- **Parte 2:** construir un endpoint seguro en C, con la filosofía *suckless*
  (código pequeño, dependencias mínimas, configuración explícita), y
  demostrar con pruebas que resiste inyección, tokens manipulados y abuso de
  solicitudes.

# Parte 1 — Análisis de vulnerabilidades en DVWA

## 1.1 Entorno y alcance

El alcance es la aplicación DVWA 2.5 en `http://127.0.0.1:8081`, con nivel de
seguridad `low`, que reproduce los fallos didácticos clásicos. Quedan fuera
del alcance el sistema operativo, la red y la base de datos como activos
independientes.

| Componente | Versión |
|---|---|
| DVWA | 2.5 |
| PHP | 8.5.12 (servidor embebido) |
| MariaDB | 11.4.13 |
| OWASP ZAP | 2.17.0 |
| Nix / nixpkgs | 2.35.1 / commit `d5cc683` |

El entorno se levanta con:

```sh
nix develop
./parte1/scripts/lab-up.sh
./parte1/scripts/run-zap.sh
./parte1/scripts/capture-evidence.sh
./parte1/scripts/lab-down.sh
```

`lab-up.sh` descarga DVWA 2.5, inicializa MariaDB en `.lab/mysql`, arranca
PHP en `127.0.0.1:8081`, crea la base `dvwa`, ejecuta `setup.php`, inicia
sesión con `admin`/`password`, fija `security=low` y comprueba el módulo
SQLi. La sesión queda en `.lab/dvwa-session.env`, que no se versiona.

> **Nota sobre el entorno:** el primer intento con Docker falló porque el
> kernel no permite cgroups anidados
> (`bpf_prog_query(BPF_CGROUP_DEVICE): function not implemented`). Se
> descartó Docker y se usó Nix, ejecutando todo como usuario normal.

## 1.2 Metodología

1. **Preparación:** DVWA + MariaDB + PHP, seguridad `low`.
2. **Autenticación de ZAP:** DVWA usa un token anti-CSRF en el login. Para no
   depender de la heurística del *form-based auth*, se inició sesión con un
   script y se inyectó la cookie en ZAP mediante `ZAP_AUTH_HEADER`,
   `ZAP_AUTH_HEADER_VALUE` y `ZAP_AUTH_HEADER_SITE`. El contexto usa
   autenticación `manual`.
3. **Descubrimiento:** un job `requestor` siembra en el historial los módulos
   que el *spider* no descubre por sí solo (endpoints AJAX como
   `get_user_data.php`); después se ejecutan *spider*, escaneo pasivo y
   escaneo activo.
4. **Validación manual:** cada hallazgo se reprodujo con `curl`, guardando
   petición, código de estado y respuesta en `parte1/evidence/`.
5. **Evaluación de riesgo:** se aplicó la plantilla de la sección 1.3.

Plan de ZAP: `parte1/zap/plan.yaml`. Informes:
`parte1/evidence/zap-report.html` y `parte1/evidence/zap-report.json`.

> El escaneo activo se ejecutó únicamente contra DVWA en localhost, una
> aplicación deliberadamente vulnerable y autorizada para este ejercicio.

## 1.3 Plantilla de evaluación de riesgos

| Campo | Descripción |
|---|---|
| **ID** | Identificador único del hallazgo |
| **Vulnerabilidad** | Nombre y descripción breve |
| **OWASP Top 10** | Categoría 2021 |
| **CWE** | Debilidad concreta |
| **Activo / endpoint** | Componente afectado |
| **Vector de ataque** | Petición o secuencia que lo explota |
| **Impacto potencial** | Confidencialidad, integridad, disponibilidad y negocio |
| **Probabilidad (1–5)** | Facilidad de explotación y exposición |
| **Impacto (1–5)** | Severidad si se explota |
| **Riesgo inherente** | Probabilidad × Impacto |
| **Nivel** | Bajo 1–4 · Medio 5–9 · Alto 10–14 · Crítico 15–25 |
| **Evidencia** | Archivo o petición reproducible |
| **Mitigación** | Controles recomendados |
| **Riesgo residual** | Riesgo esperado tras aplicar los controles |

## 1.4 Hallazgos

### A4-P1-01 — SQL Injection en `/vulnerabilities/sqli/`

| Campo | Valor |
|---|---|
| **ID** | A4-P1-01 |
| **Vulnerabilidad** | Inyección SQL clásica por concatenación de `id` en `SELECT first_name, last_name FROM users WHERE user_id = '$id'` |
| **OWASP Top 10** | A03:2021 — Injection |
| **CWE** | CWE-89 |
| **Activo / endpoint** | `GET /vulnerabilities/sqli/?id=...&Submit=Submit` |
| **Vector** | `id=1' UNION SELECT user, password FROM users -- -` |
| **Impacto potencial** | Lectura completa de la tabla `users`, incluidos hashes MD5 de contraseñas; con consultas de escritura, alteración o borrado. Confidencialidad **alta**, integridad **alta**, disponibilidad **media**. Permite cracking offline y reutilización de credenciales. |
| **Probabilidad** | 4 — requiere sesión, pero el laboratorio usa credenciales por defecto y el fallo se explota con una sola petición |
| **Impacto** | 5 — exposición de credenciales y datos de todos los usuarios |
| **Riesgo inherente** | **20 / Crítico** |
| **Evidencia** | `parte1/evidence/manual-sqli.txt` y `manual-sqli.html`; ZAP reporta *SQL Injection* sobre `id`. |
| **Mitigación** | Consultas preparadas, validación de `id` como entero positivo, usuario de BD con privilegios mínimos, ocultar errores SQL, WAF y SAST/DAST en CI. |
| **Riesgo residual** | Bajo (2–4) con consultas preparadas y mínimo privilegio |

Respuesta observada (resumida):

```text
First name: admin   | Surname: 903a98d709fa4683aaaa036b84c125a6
First name: gordonb | Surname: e99a18c428cb38d5f260853678922e03
First name: 1337    | Surname: 8d3533d75ae2c3966d7e0d4fcc69216b
First name: pablo   | Surname: 0d107d09f5bbe40cade3de5c71e9e9b7
First name: smithy  | Surname: 5f4dcc3b5aa765d61d8327deb882cf99
```

Los valores de `password` son hashes MD5 sin *salt*; el último corresponde a
`password`.

![Inyección SQL en DVWA: la consulta `UNION` devuelve los hashes MD5 de todos los usuarios.](docs/screenshots/01-sqli.png){width=95%}

### A4-P1-02 — XSS reflejado en `/vulnerabilities/xss_r/`

| Campo | Valor |
|---|---|
| **ID** | A4-P1-02 |
| **Vulnerabilidad** | `name` se concatena sin codificar dentro de `<pre>Hello ...</pre>` y la respuesta desactiva el filtro con `X-XSS-Protection: 0` |
| **OWASP Top 10** | A03:2021 — Injection |
| **CWE** | CWE-79 |
| **Activo / endpoint** | `GET /vulnerabilities/xss_r/?name=...` |
| **Vector** | `name=<script>alert(document.cookie)</script>`; también un `onerror` en `<img>` |
| **Impacto potencial** | Robo de `PHPSESSID` (sin `HttpOnly`), del token CSRF y ejecución de acciones como la víctima; phishing y desfiguración. Confidencialidad **alta**, integridad **media**, disponibilidad **baja**. |
| **Probabilidad** | 4 — el enlace malicioso se envía a una víctima autenticada |
| **Impacto** | 4 — secuestro de sesión y acciones en nombre de la víctima |
| **Riesgo inherente** | **16 / Crítico** |
| **Evidencia** | `parte1/evidence/manual-xss.txt` y `manual-xss.html`; ZAP reporta *Cross Site Scripting (Reflected)*. |
| **Mitigación** | Codificación contextual de salida (`htmlspecialchars(..., ENT_QUOTES, 'UTF-8')`), CSP restrictiva, cookies `HttpOnly; Secure; SameSite=Lax`, validación por allowlist y evitar `innerHTML`/`document.write`. |
| **Riesgo residual** | Bajo (2–4) con codificación de salida y CSP |

Respuesta observada:

```html
<pre>Hello <script>alert(document.cookie)</script></pre>
```

![XSS reflejado: el script se ejecuta y escribe la cookie de sesión (`PHPSESSID`) dentro de la página.](docs/screenshots/02-xss.png){width=95%}

### A4-P1-03 — Broken Access Control / IDOR en `/vulnerabilities/authbypass/`

| Campo | Valor |
|---|---|
| **ID** | A4-P1-03 |
| **Vulnerabilidad** | `get_user_data.php` y `change_user_details.php` no exigen sesión ni rol: en `low`/`medium` solo comprueban el rol en `high`/`impossible`. La lectura devuelve todos los usuarios y la escritura actualiza cualquier `user_id` |
| **OWASP Top 10** | A01:2021 — Broken Access Control |
| **CWE** | CWE-306, CWE-862, CWE-639 |
| **Activo / endpoint** | `GET /vulnerabilities/authbypass/get_user_data.php` y `POST /vulnerabilities/authbypass/change_user_details.php` |
| **Vector** | Petición directa **sin cookie** a `get_user_data.php`; para escritura, `POST` JSON con `id`, `first_name` y `surname` de cualquier usuario |
| **Impacto potencial** | Enumeración de usuarios y datos personales; modificación no autorizada de perfiles; escalada de privilegios y toma de cuentas si se combina con otros módulos. Confidencialidad **alta**, integridad **alta**, disponibilidad **baja**. |
| **Probabilidad** | 5 — no requiere autenticación y el endpoint es accesible directamente |
| **Impacto** | 4 — datos de todos los usuarios y escritura arbitraria |
| **Riesgo inherente** | **20 / Crítico** |
| **Evidencia** | `parte1/evidence/manual-authbypass.txt` y `manual-authbypass.json` |
| **Mitigación** | Middleware central de autenticación y autorización para **todas** las rutas, denegar por defecto, comprobación a nivel de objeto, sesión de servidor y CSRF en escrituras, consultas preparadas, auditoría y pruebas de autorización en CI. |
| **Riesgo residual** | Bajo (2–4) con autorización centralizada y pruebas negativas |

Respuesta observada (sin sesión, `200 OK`):

```json
[{"user_id":"1","first_name":"admin","surname":"admin"},
 {"user_id":"2","first_name":"Gordon","surname":"Brown"},
 {"user_id":"3","first_name":"Hack","surname":"Me"},
 {"user_id":"4","first_name":"Pablo","surname":"Picasso"},
 {"user_id":"5","first_name":"Bob","surname":"Smith"}]
```

![Control de acceso roto: `get_user_data.php` devuelve todos los usuarios en una petición sin cookie de sesión.](docs/screenshots/03-authbypass.png){width=95%}

`change_user_details.php` también concatena los valores en la consulta de
escritura:

```php
$query = "UPDATE users SET first_name = '" . $data->first_name .
         "', last_name = '" . $data->surname .
         "' where user_id = " . $data->id;
```

## 1.5 Hallazgos de ZAP

El informe de ZAP 2.17.0 confirma los tres fallos principales y añade
problemas de configuración: **SQL Injection** (40018, alto) sobre `id`,
**Cross Site Scripting (Reflected)** (40012, alto) y **DOM Based** (40026,
alto) sobre `name`, ausencia de tokens anti-CSRF (10202, 5 instancias),
divulgación de errores de aplicación (90022, 12), CSP ausente o incompleta
(10038/10055), falta de cabecera anti-clickjacking (10020), cookies sin
`HttpOnly`/`SameSite`, fuga de versión en `X-Powered-By` y ausencia de
`X-Content-Type-Options`. La alerta *Cloud Metadata Potentially Exposed*
(90034) es un falso positivo: el servidor de laboratorio redirige cualquier
ruta desconocida a `login.php`. ZAP no detecta el control de acceso roto
porque es un fallo de lógica, sin firma reconocible; por eso se validó
manualmente.

![Resumen del informe de ZAP 2.17.0: 4 alertas de riesgo alto, 9 medias, 7 bajas y 6 informativas sobre `127.0.0.1:8081`.](docs/screenshots/04-zap.png){width=100%}

## 1.6 Limitaciones de la parte 1

- DVWA es deliberadamente vulnerable; los resultados no se extrapolan
  directamente a un sistema productivo.
- El nivel `low` maximiza la exposición con fines didácticos. Los niveles
  `medium`, `high` e `impossible` reducen o eliminan varios fallos y pueden
  usarse como comparación.
- El escaneo se ejecutó contra `127.0.0.1`; no se probó ningún sistema de
  terceros.
- ZAP no detecta por sí solo todos los fallos de lógica; por eso
  `get_user_data.php` se validó manualmente.

# Parte 2 — API segura en C

## 2.1 Diseño y filosofía suckless

La API se implementó en un único archivo `parte2/api.c`, usando solo libc y
POSIX. No hay frameworks, ORM, SQL, `system()` ni dependencias externas. La
configuración vive en `config.def.h`; los secretos se leen del entorno. El
binario se compila con:

```sh
cd parte2
nix develop .. -c make
A4_JWT_SECRET='...' A4_CLIENT_SECRET='...' ./api
```

| Variable | Valor por defecto | Uso |
|---|---|---|
| `A4_PORT` | `8080` | puerto en `127.0.0.1` |
| `A4_JWT_SECRET` | secreto de laboratorio | clave HS256 |
| `A4_CLIENT_SECRET` | secreto de laboratorio | secreto OAuth del cliente |
| `A4_RATE_LIMIT` | `100` | solicitudes por ventana y credencial/IP |
| `A4_RATE_WINDOW` | `60` | segundos de la ventana |

Los valores por defecto son de laboratorio; en producción se deben inyectar
secretos fuertes y poner el binario detrás de TLS.

## 2.2 Endpoints

| Método | Ruta | Autenticación | Descripción |
|---|---|---|---|
| `GET` | `/healthz` | — | sonda de vida |
| `POST` | `/oauth/token` | cliente OAuth | *client credentials*, devuelve JWT |
| `GET` | `/api/v1/profile` | JWT (`read`) | identidad y scopes |
| `POST` | `/api/v1/transfers` | JWT (`transfer`) | transferencia simulada y validada |

Ejemplo de obtención de token:

```sh
curl -s -X POST http://127.0.0.1:8080/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'grant_type=client_credentials&client_id=demo-client&client_secret=...&scope=read transfer'
```

Respuesta:

```json
{"access_token":"eyJ...","token_type":"Bearer","expires_in":900,"scope":"read transfer"}
```

![Flujo real de la API: obtención del JWT, consulta de perfil, transferencia válida, intento de inyección SQL rechazado y límite de tasa con `429` + `Retry-After`.](docs/screenshots/05-flujo-api.png){width=100%}

## 2.3 OAuth 2.0 y JWT

- Grant `client_credentials` (RFC 6749 §4.4), con `client_id` y
  `client_secret` comparados en tiempo constante.
- Scopes permitidos: `read` y `transfer`; cualquier otro devuelve
  `invalid_scope`.
- JWT **HS256** exclusivamente: se rechaza `alg: none`, algoritmos distintos
  y tokens sin firma.
- Claims obligatorios: `iss`, `aud`, `sub`, `scope`, `iat`, `exp`, `jti`.
- Se valida la firma HMAC-SHA-256 en tiempo constante, el emisor, la
  audiencia, la expiración, `iat` no futuro y la vida máxima del token.
- `jti` se genera con 16 bytes de `/dev/urandom`; TTL de 900 s.

La implementación incluye SHA-256 y HMAC-SHA-256 propios para no enlazar
OpenSSL y mantener el binario pequeño.

## 2.4 Validación de entradas

La ruta de transferencias acepta únicamente:

```json
{"account":"ABC-1234","amount":250}
```

Reglas:

- `Content-Type: application/json` (se acepta un parámetro `charset`).
- Cuerpo máximo de 1024 bytes; `Content-Length` obligatorio y estricto.
- Parser JSON plano propio: solo objeto, strings ASCII imprimibles y enteros.
  Rechaza duplicados, campos desconocidos, controles, UTF-8 no ASCII,
  `null`, booleanos, floats, exponentes y ceros a la izquierda.
- `account`: exactamente `^[A-Z]{3}-[0-9]{4}$`.
- `amount`: entero entre 1 y 1 000 000.
- No hay SQL, `system()` ni rutas de archivo: la inyección no tiene
  superficie de ejecución y, aun así, se rechaza en la frontera.

La validación se probó con payloads de SQLi, XSS, *command injection* y
*path traversal*; todos devuelven `400` con un campo de error genérico, sin
reflejar la entrada.

## 2.5 Rate limiting

- 100 solicitudes por minuto y por credencial (`sub` del JWT).
- 100 solicitudes por minuto y por IP en `/oauth/token` y en `/api/*`
  (cubos separados).
- Ventana fija; al exceder se responde `429` con `Retry-After`.
- Tabla hash de 1024 entradas con sondeo lineal; si se llena, falla cerrado.

## 2.6 Pruebas y resultados

`parte2/tests/test_api.py` usa solo la biblioteca estándar de Python y cubre
51 casos: OAuth, JWT (firma/alg/exp/iss/aud/scope), SQLi, XSS, *command
injection*, *path traversal*, JSON malformado, tipos incorrectos, tamaños
máximos, *content-type*, 404, 100 req/min, `429` + `Retry-After` y reinicio
de ventana.

```sh
cd parte2
nix develop .. -c make test
```

Resultado final: **51/51 pruebas correctas**. Evidencia:
`parte2/evidence/test-results.txt`.

![Salida de `make test`: 51/51 pruebas correctas, incluidas las de OAuth, JWT, inyección y rate limiting.](docs/screenshots/06-pruebas-api.png){width=90%}

También se incluye `parte2/postman_collection.json` para probar el flujo
desde Postman: primero se ejecuta **OAuth 2.0 → Token** (guarda
`accessToken`) y después las peticiones de **API**.

## 2.7 Decisiones de seguridad y límites

- Un solo hilo y una conexión por solicitud: suficiente para el laboratorio;
  un despliegue real debería usar `poll`/`epoll` o un pool.
- Sin TLS: debe ir detrás de un terminador TLS.
- Sin persistencia ni revocación de `jti`: el estado de *rate limiting* es en
  memoria y se reinicia con el proceso.
- Hardening de compilación: `-fstack-protector-strong`,
  `-D_FORTIFY_SOURCE=2`, PIE, `RELRO` completo y `-Werror`.
- No se registran tokens, secretos ni cuerpos de solicitud.

# Conclusiones

La parte 1 confirma que los fallos clásicos siguen siendo explotables con
herramientas estándar: una sola petición permitió extraer todos los usuarios
y sus hashes, un enlace reflejó JavaScript arbitrario y un endpoint AJAX
expuso datos sin sesión. La lección principal es que la validación de
entradas y la autorización deben aplicarse en el servidor, de forma
centralizada, y no confiar en controles del cliente.

La parte 2 demuestra que es posible construir una API pequeña y auditable en
C sin renunciar a controles esenciales: OAuth 2.0, JWT firmados, validación
estricta, autorización por scopes y *rate limiting*. Las 51 pruebas
automatizadas convierten esas propiedades en algo verificable, no solo
declarativo. La combinación de ambas partes muestra el contraste entre una
aplicación vulnerable y una API endurecida, y proporciona una base
reproducible para seguir trabajando en la parte 3 (pfSense/Snort) y la parte
4 (matriz de riesgos 5×5).

# Referencias

- OWASP. *OWASP Top 10:2021*. <https://owasp.org/Top10/>
- OWASP. *Cross Site Scripting Prevention Cheat Sheet*.
- OWASP. *SQL Injection Prevention Cheat Sheet*.
- OWASP. *Authorization Cheat Sheet*.
- IETF. *RFC 6749 — The OAuth 2.0 Authorization Framework*.
- IETF. *RFC 7519 — JSON Web Token (JWT)*.
- IETF. *RFC 6234 — US Secure Hash Algorithms*.
- *suckless.org — software that sucks less*.
- OWASP ZAP. *Automation Framework*. <https://www.zaproxy.org/docs/>

# Anexos

## A. Comandos de reproducción

```sh
# Laboratorio completo
nix develop
./parte1/scripts/lab-up.sh
./parte1/scripts/run-zap.sh
./parte1/scripts/capture-evidence.sh

# API y pruebas
cd parte2
nix develop .. -c make test

# Capturas del informe (con el laboratorio levantado)
cd ..
nix develop .#screenshots -c python3 scripts/capture-screenshots.py

# Compilar el informe
make
```

## B. Archivos de evidencia

| Archivo | Contenido |
|---|---|
| `parte1/evidence/zap-report.html` | Informe HTML de ZAP |
| `parte1/evidence/zap-report.json` | Informe JSON de ZAP |
| `parte1/evidence/manual-sqli.txt` | Evidencia de SQLi |
| `parte1/evidence/manual-xss.txt` | Evidencia de XSS |
| `parte1/evidence/manual-authbypass.txt` | Evidencia de control de acceso roto |
| `parte2/evidence/test-results.txt` | Resultado de las 51 pruebas |
| `docs/screenshots/01-sqli.png` | Captura de la inyección SQL |
| `docs/screenshots/02-xss.png` | Captura del XSS reflejado |
| `docs/screenshots/03-authbypass.png` | Captura del control de acceso roto |
| `docs/screenshots/04-zap.png` | Resumen del informe de ZAP |
| `docs/screenshots/05-flujo-api.png` | Flujo OAuth 2.0/JWT/validación |
| `docs/screenshots/06-pruebas-api.png` | Salida de las pruebas de la API |
| `scripts/capture-screenshots.py` | Generador reproducible de las capturas |
| `docs/bitacora.md` | Procedimiento cronológico y decisiones |
