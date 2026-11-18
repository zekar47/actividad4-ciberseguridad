# Parte 2 — API segura en C (OAuth 2.0 + JWT + validación + rate limiting)

Implementación de un endpoint HTTP mínimo en C11, sin frameworks y con una
única dependencia externa: `libcrypto` de OpenSSL para HMAC-SHA-256. El
resto del código usa solo libc/POSIX. Sigue la filosofía *suckless*: un único
binario, configuración en `config.def.h`, código legible y herramientas
pequeñas que hacen una sola cosa. La criptografía se delega a una biblioteca
auditada en lugar de reimplementarla.

## Arranque rápido

```sh
cd parte2
nix develop .. -c make          # compila ./api
A4_JWT_SECRET='...' A4_CLIENT_SECRET='...' ./api
```

| Variable | Valor por defecto | Uso |
|---|---|---|
| `A4_PORT` | `8080` | puerto de escucha en `127.0.0.1` |
| `A4_JWT_SECRET` | secreto de laboratorio | clave HS256 |
| `A4_CLIENT_SECRET` | secreto de laboratorio | secreto OAuth del cliente |
| `A4_RATE_LIMIT` | `100` | solicitudes por ventana y credencial/IP |
| `A4_RATE_WINDOW` | `60` | segundos de la ventana |

> Los valores por defecto son deliberadamente de laboratorio. En un despliegue
> real se deben inyectar secretos fuertes y poner el binario detrás de TLS.

## Endpoints

| Método | Ruta | Autenticación | Descripción |
|---|---|---|---|
| `GET` | `/healthz` | — | sonda de vida |
| `POST` | `/oauth/token` | cliente OAuth | *client credentials*, devuelve JWT |
| `GET` | `/api/v1/profile` | JWT (`read`) | identidad y scopes del token |
| `POST` | `/api/v1/transfers` | JWT (`transfer`) | transferencia simulada y validada |

### OAuth 2.0

```sh
curl -s -X POST http://127.0.0.1:8080/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'grant_type=client_credentials&client_id=demo-client&client_secret=...&scope=read transfer'
```

Respuesta:

```json
{"access_token":"eyJ...","token_type":"Bearer","expires_in":900,"scope":"read transfer"}
```

El endpoint implementa el grant `client_credentials` de OAuth 2.0
(RFC 6749 §4.4), valida `client_id`/`client_secret` en tiempo constante y
solo emite scopes de la allowlist (`read`, `transfer`). Los errores usan el
formato OAuth (`invalid_client`, `invalid_scope`, `unsupported_grant_type`).

### JWT

- Algoritmo: **HS256** exclusivamente. Se rechaza `alg: none`, algoritmos
  distintos y tokens sin firma.
- Claims obligatorios: `iss`, `aud`, `sub`, `scope`, `iat`, `exp`, `jti`.
- Se valida firma HMAC-SHA-256 en tiempo constante, emisor, audiencia,
  expiración, `iat` no futuro y vida máxima del token.
- `jti` se genera con 16 bytes de `/dev/urandom`.
- TTL: 900 s.

### Validación de entradas

La ruta de transferencias acepta únicamente:

```json
{"account":"ABC-1234","amount":250}
```

Reglas:

- `Content-Type: application/json` (se acepta parámetro `charset`).
- Cuerpo máximo de 1024 bytes; `Content-Length` obligatorio y estricto.
- Parser JSON plano propio: solo objeto, strings ASCII imprimibles y enteros.
  Rechaza duplicados, campos desconocidos, controles, UTF-8 no ASCII,
  `null`, booleanos, floats, exponentes y ceros a la izquierda.
- `account`: exactamente `^[A-Z]{3}-[0-9]{4}$`.
- `amount`: entero entre 1 y 1 000 000.
- No hay SQL, ni `system()`, ni rutas de archivo: la inyección no tiene
  superficie de ejecución, y aun así se rechaza en la frontera.

### Rate limiting

- 100 solicitudes por minuto y por credencial (`sub` del JWT).
- 100 solicitudes por minuto y por IP en `/oauth/token` y en `/api/*`
  (cubos separados).
- Ventana fija; al exceder se responde `429` con `Retry-After`.
- Tabla hash de 1024 entradas con sondeo lineal; si se llena, falla cerrado.

## Pruebas

```sh
cd parte2
nix develop .. -c make test
```

`tests/test_api.py` usa solo la biblioteca estándar de Python y cubre 51 casos:
OAuth, JWT (firma/alg/exp/iss/aud/scope), XSS, SQLi, command injection,
path traversal, JSON malformado, tipos incorrectos, tamaños máximos,
content-type, 404, 100 req/min, 429 + `Retry-After` y reinicio de ventana.
El resultado se guarda en `evidence/test-results.txt`.

## Postman

Importar `postman_collection.json`. Ejecutar primero
**OAuth 2.0 → Token (client credentials)**: el script de test guarda
`accessToken` como variable de colección. Después se pueden ejecutar las
peticiones de la carpeta **API**.

## Decisiones de seguridad y límites

- Un solo hilo y una conexión por solicitud: suficiente para el laboratorio;
  un despliegue real debería usar `poll`/`epoll` o un pool.
- Sin TLS: debe ir detrás de un terminador TLS.
- Sin persistencia ni revocación de `jti`: el estado de rate limiting es en
  memoria y se reinicia con el proceso.
- La comparación de secretos es en tiempo constante para evitar *timing
  attacks*; la longitud de los secretos sí puede filtrarse por el tamaño de
  la comparación, algo irrelevante con secretos de tamaño fijo.
- Hardening de compilación: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`,
  PIE, `RELRO` completo, `-Werror`.
- No se registran tokens, secretos ni cuerpos de solicitud.
