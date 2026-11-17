# Parte 1 — Análisis de vulnerabilidades en DVWA con OWASP ZAP

## 1. Objetivo y alcance

Se evaluó **Damn Vulnerable Web Application (DVWA) 2.5** en un laboratorio
local, con el nivel de seguridad `low` (el nivel didáctico que reproduce los
fallos clásicos). El alcance es la aplicación web en
`http://127.0.0.1:8081`; quedan fuera el sistema operativo, la red y la base
de datos como activos independientes.

Se identificaron y validaron manualmente tres vulnerabilidades del
**OWASP Top 10:2021**, además de los hallazgos complementarios que reportó
ZAP:

1. **A03:2021 — Injection**: SQL Injection en el módulo `sqli`.
2. **A03:2021 — Injection**: Cross-Site Scripting reflejado en `xss_r`.
3. **A01:2021 — Broken Access Control**: lectura (y modificación) de usuarios
   sin autenticación en el módulo `authbypass`.

## 2. Entorno reproducible

El laboratorio no usa contenedores porque el kernel del equipo anfitrión no
permite crear cgroups anidados (`bpf_prog_query(BPF_CGROUP_DEVICE): function
not implemented`). En su lugar se usa un **flake de Nix** que fija todas las
versiones y ejecuta los servicios como el usuario normal, sin `sudo`:

| Componente | Versión |
|---|---|
| DVWA | 2.5 (release oficial de `digininja/DVWA`) |
| PHP | 8.5.12 (servidor embebido, sin Apache) |
| MariaDB | 11.4.13 (datadir y socket dentro de `.lab/`) |
| OWASP ZAP | 2.17.0 |
| Nix | 2.35.1, nixpkgs fijado en `flake.lock` |

```sh
nix develop                       # carga php, mariadb, zap, curl, jq, python3
./parte1/scripts/lab-up.sh        # MariaDB + PHP + DVWA + sesión autenticada
./parte1/scripts/run-zap.sh       # escaneo automatizado (puede tardar minutos)
./parte1/scripts/capture-evidence.sh
./parte1/scripts/lab-down.sh
```

`lab-up.sh` descarga DVWA 2.5, inicializa MariaDB en `.lab/mysql`, levanta PHP
en `127.0.0.1:8081`, crea la base `dvwa`, ejecuta `setup.php`, inicia sesión
con las credenciales de laboratorio `admin`/`password`, fija
`security=low` y comprueba el módulo SQLi. La sesión queda en
`.lab/dvwa-session.env` (ignorado por Git).

## 3. Metodología

1. **Preparación**: DVWA 2.5 + MariaDB + PHP, seguridad `low`.
2. **Autenticación de ZAP**: la aplicación usa un token anti-CSRF en el
   formulario de login. Para no depender de la heurística del *form-based
   auth*, se inició sesión con un script y se inyectó la cookie resultante en
   ZAP mediante las variables oficiales `ZAP_AUTH_HEADER`,
   `ZAP_AUTH_HEADER_VALUE` y `ZAP_AUTH_HEADER_SITE`. El contexto usa
   autenticación `manual`.
3. **Descubrimiento**: `requestor` siembra en el historial los módulos que el
   *spider* no descubre por sí solo (endpoints AJAX como `get_user_data.php`);
   después se ejecuta el *spider* y el escaneo pasivo/activo.
4. **Validación manual**: cada hallazgo se reprodujo con `curl`, guardando
   petición, código de estado y respuesta en `evidence/`.
5. **Evaluación de riesgo**: se aplicó la plantilla de la sección 4.

Plan de ZAP: [`zap/plan.yaml`](zap/plan.yaml). Informes:
[`evidence/zap-report.html`](evidence/zap-report.html) y
[`evidence/zap-report.json`](evidence/zap-report.json).

> El escaneo activo se ejecutó únicamente contra DVWA en localhost, una
> aplicación deliberadamente vulnerable y autorizada para este ejercicio.

## 4. Plantilla de evaluación de riesgos

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

## 5. Hallazgos

### A4-P1-01 — SQL Injection en `/vulnerabilities/sqli/`

| Campo | Valor |
|---|---|
| **ID** | A4-P1-01 |
| **Vulnerabilidad** | Inyección SQL clásica por concatenación de `id` en la consulta `SELECT first_name, last_name FROM users WHERE user_id = '$id'` |
| **OWASP Top 10** | A03:2021 — Injection |
| **CWE** | CWE-89: SQL Injection |
| **Activo / endpoint** | `GET /vulnerabilities/sqli/?id=...&Submit=Submit` |
| **Vector** | `id=1' UNION SELECT user, password FROM users -- -` |
| **Impacto potencial** | Lectura completa de la tabla `users`, incluidos hashes MD5 de contraseñas; con consultas de escritura, alteración o borrado de datos. Confidencialidad **alta**, integridad **alta**, disponibilidad **media**. Permite cracking offline y reutilización de credenciales. |
| **Probabilidad** | 4 — requiere sesión, pero el laboratorio usa credenciales por defecto y el fallo se explota con una sola petición |
| **Impacto** | 5 — exposición de credenciales y datos de todos los usuarios |
| **Riesgo inherente** | **20 / Crítico** |
| **Evidencia** | [`evidence/manual-sqli.txt`](evidence/manual-sqli.txt) y [`evidence/manual-sqli.html`](evidence/manual-sqli.html). ZAP reporta *SQL Injection* sobre el parámetro `id`. |
| **Mitigación** | Consultas preparadas con parámetros vinculados (PDO/mysqli), validación de `id` como entero positivo, usuario de BD con privilegios mínimos (solo `SELECT` sobre las columnas necesarias), ocultar errores SQL, WAF y pruebas SAST/DAST en CI. |
| **Riesgo residual** | Bajo (2–4) si se aplican consultas preparadas y mínimo privilegio |

Respuesta observada (resumida):

```text
First name: admin   | Surname: 903a98d709fa4683aaaa036b84c125a6
First name: gordonb | Surname: e99a18c428cb38d5f260853678922e03
First name: 1337    | Surname: 8d3533d75ae2c3966d7e0d4fcc69216b
First name: pablo   | Surname: 0d107d09f5bbe40cade3de5c71e9e9b7
First name: smithy  | Surname: 5f4dcc3b5aa765d61d8327deb882cf99
```

Los valores de la columna `password` son hashes MD5 sin *salt*; el último, por
ejemplo, corresponde a `password`.

### A4-P1-02 — XSS reflejado en `/vulnerabilities/xss_r/`

| Campo | Valor |
|---|---|
| **ID** | A4-P1-02 |
| **Vulnerabilidad** | El parámetro `name` se concatena sin codificar dentro de `<pre>Hello ...</pre>` y la respuesta desactiva el filtro del navegador con `X-XSS-Protection: 0` |
| **OWASP Top 10** | A03:2021 — Injection |
| **CWE** | CWE-79: Cross-site Scripting (Reflected) |
| **Activo / endpoint** | `GET /vulnerabilities/xss_r/?name=...` |
| **Vector** | `name=<script>alert(document.cookie)</script>`; también funciona un `onerror` en un `<img>` |
| **Impacto potencial** | Robo de la cookie de sesión (`PHPSESSID`, sin `HttpOnly`), del token CSRF y ejecución de acciones como la víctima; phishing y desfiguración. Confidencialidad **alta**, integridad **media**, disponibilidad **baja**. |
| **Probabilidad** | 4 — el enlace malicioso se envía a una víctima autenticada |
| **Impacto** | 4 — secuestro de sesión y acciones en nombre de la víctima |
| **Riesgo inherente** | **16 / Crítico** |
| **Evidencia** | [`evidence/manual-xss.txt`](evidence/manual-xss.txt) y [`evidence/manual-xss.html`](evidence/manual-xss.html). ZAP reporta *Cross Site Scripting (Reflected)*. |
| **Mitigación** | Codificación contextual de salida (`htmlspecialchars(..., ENT_QUOTES, 'UTF-8')`), CSP con `script-src` restrictivo, cookies `HttpOnly; Secure; SameSite=Lax`, validación por allowlist y evitar `innerHTML`/`document.write`. |
| **Riesgo residual** | Bajo (2–4) con codificación de salida y CSP |

Respuesta observada:

```html
<pre>Hello <script>alert(document.cookie)</script></pre>
```

### A4-P1-03 — Broken Access Control / IDOR en `/vulnerabilities/authbypass/`

| Campo | Valor |
|---|---|
| **ID** | A4-P1-03 |
| **Vulnerabilidad** | `get_user_data.php` y `change_user_details.php` no exigen sesión ni rol: en `low`/`medium` solo comprueban el rol en `high`/`impossible`. La lectura devuelve todos los usuarios y la escritura actualiza cualquier `user_id` |
| **OWASP Top 10** | A01:2021 — Broken Access Control |
| **CWE** | CWE-306 (Missing Authentication), CWE-862 (Missing Authorization), CWE-639 (IDOR) |
| **Activo / endpoint** | `GET /vulnerabilities/authbypass/get_user_data.php` y `POST /vulnerabilities/authbypass/change_user_details.php` |
| **Vector** | Petición directa **sin cookie**: `curl http://127.0.0.1:8081/vulnerabilities/authbypass/get_user_data.php`. Para escritura, `POST` JSON con `id`, `first_name` y `surname` de cualquier usuario |
| **Impacto potencial** | Enumeración de usuarios y datos personales; modificación no autorizada de perfiles; escalada de privilegios y toma de cuentas si se combina con otros módulos. Confidencialidad **alta**, integridad **alta**, disponibilidad **baja**. |
| **Probabilidad** | 5 — no requiere autenticación y el endpoint es accesible directamente |
| **Impacto** | 4 — datos de todos los usuarios y escritura arbitraria |
| **Riesgo inherente** | **20 / Crítico** |
| **Evidencia** | [`evidence/manual-authbypass.txt`](evidence/manual-authbypass.txt) y [`evidence/manual-authbypass.json`](evidence/manual-authbypass.json) |
| **Mitigación** | Middleware central de autenticación y autorización para **todas** las rutas, denegar por defecto, comprobación a nivel de objeto (el usuario solo accede a su propio `id`), sesión de servidor y CSRF en operaciones de escritura, consultas preparadas, registro de auditoría y pruebas de autorización en CI. |
| **Riesgo residual** | Bajo (2–4) con autorización centralizada y pruebas negativas |

Respuesta observada (sin sesión, `200 OK`):

```json
[{"user_id":"1","first_name":"admin","surname":"admin"},
 {"user_id":"2","first_name":"Gordon","surname":"Brown"},
 {"user_id":"3","first_name":"Hack","surname":"Me"},
 {"user_id":"4","first_name":"Pablo","surname":"Picasso"},
 {"user_id":"5","first_name":"Bob","surname":"Smith"}]
```

En `change_user_details.php` la consulta de escritura también concatena los
valores:

```php
$query = "UPDATE users SET first_name = '" . $data->first_name .
         "', last_name = '" . $data->surname .
         "' where user_id = " . $data->id;
```

## 6. Hallazgos de ZAP

El informe de ZAP 2.17.0 (`evidence/zap-report.html` y `.json`) confirma los
tres hallazgos principales y añade problemas de configuración y cabeceras:

| Riesgo | Alerta (plugin) | Instancias |
|---|---|---|
| Alto | **SQL Injection** (40018) — parámetro `id` | 1 |
| Alto | **Cross Site Scripting (Reflected)** (40012) — parámetro `name` | 1 |
| Alto | **Cross Site Scripting (DOM Based)** (40026) — mismo módulo | 1 |
| Medio | Absence of Anti-CSRF Tokens (10202) | 5 |
| Medio | Application Error Disclosure (90022) | 12 |
| Medio | CSP ausente o incompleta (10038 / 10055) | 5 + 12 |
| Medio | Missing Anti-clickjacking Header (10020) | 5 |
| Medio | Hidden File Found (40035) — `phpinfo.php` | 1 |
| Medio | Sub Resource Integrity Attribute Missing (90003) | 2 |
| Bajo | Cookie sin `HttpOnly` (10010) / sin `SameSite` (10054) | 5 + 5 |
| Bajo | Fuga de versión en `X-Powered-By` (10037) | 5 |
| Bajo | `X-Content-Type-Options` ausente (10021) | 5 |
| Bajo | Debug Error Messages (10023) | 13 |
| Bajo | Cross-Domain JavaScript Source File Inclusion (10017) | 2 |
| Informativo | Authentication Request Identified (10111), Session Management (10112), User Controllable HTML Element Attribute (10031) | — |

La alerta **Cloud Metadata Potentially Exposed** (90034) es un **falso
positivo**: el servidor de laboratorio redirige (`302`) cualquier ruta
desconocida a `login.php`, y ZAP interpreta esa redirección como acceso a
metadatos. `Hidden File Found` corresponde a `phpinfo.php`, que DVWA incluye
a propósito; en un despliegue real debería eliminarse.

ZAP no detecta por sí solo el control de acceso roto de
`get_user_data.php`, porque el fallo es de lógica (falta de autorización) y no
deja una firma reconocible; por eso ese hallazgo se validó manualmente. Los
detalles de configuración y cabeceras se conservan como línea base antes de
aplicar mitigaciones.

## 7. Limitaciones

- DVWA es una aplicación deliberadamente vulnerable; los resultados no se
  extrapolan directamente a un sistema productivo.
- El nivel `low` maximiza la exposición para fines didácticos. Los niveles
  `medium`/`high`/`impossible` reducen o eliminan varios de estos fallos y
  pueden usarse como comparación.
- El escaneo se ejecutó contra `127.0.0.1`; no se probó ningún sistema de
  terceros.
- ZAP no detecta por sí solo todos los fallos de lógica (por eso
  `get_user_data.php` se validó manualmente).
