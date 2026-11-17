#ifndef A4_CONFIG_H
#define A4_CONFIG_H

/* Configuración de compilación (filosofía suckless: sin archivos de config
 * en tiempo de ejecución salvo los secretos, que sí se leen del entorno). */

#define LISTEN_ADDR "127.0.0.1"
#define LISTEN_PORT 8080

#define HTTP_HEADER_MAX 8192
#define HTTP_BODY_MAX 1024
#define JWT_MAX 2048
#define JWT_TTL 900                 /* 15 minutos */
#define JWT_CLOCK_SKEW 60
#define JWT_MAX_LIFETIME 3600

#define JWT_ISSUER "https://auth.a4.local"
#define JWT_AUDIENCE "a4-api"

#define OAUTH_CLIENT_ID "demo-client"
#define OAUTH_SCOPE_DEFAULT "read"
#define OAUTH_SCOPE_ALLOWED "read transfer"

#define RATE_LIMIT 100              /* solicitudes por ventana y credencial/IP */
#define RATE_WINDOW 60              /* segundos */
#define RATE_SLOTS 1024

#define REQ_TIMEOUT_SEC 10

/* Valores por defecto SOLO para el laboratorio. En producción se deben
 * sobrescribir con A4_JWT_SECRET / A4_CLIENT_SECRET. */
#define JWT_SECRET_DEFAULT "lab-only-jwt-secret-change-me-32bytes"
#define CLIENT_SECRET_DEFAULT "lab-only-client-secret-change-me"

#endif
