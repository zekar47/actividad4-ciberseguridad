# Parte 3 — Perímetro con pfSense, Snort y filtrado de contenido

## Topología

Se virtualiza pfSense CE 2.7.2 con cuatro interfaces virtio bajo KVM/QEMU:

| Interfaz | Red | Función |
|---|---|---|
| `vtnet0` (WAN) | DHCP `10.0.2.15/24` (user-mode) | salida a Internet |
| `vtnet1` (LAN) | `192.168.1.1/24` | administración, GUI en `https://127.0.0.1:8443` |
| `vtnet2` (OPT1) | `192.168.10.1/24` | VLAN no confiable (atacante `192.168.10.10`) |
| `vtnet3` (OPT2) | `192.168.20.1/24` | VLAN interna (servidor `192.168.20.10`) |

OPT1 y OPT2 se conectan mediante *socket hubs* de QEMU en los puertos
`10001` y `10002`. El atacante arranca con una segunda NIC en la red
user-mode solo para instalar `nmap`; el tráfico del ataque sale por `eth0`.

## Arranque

```sh
# Terminal 1: pfSense
nix develop .#parte3 -c tmux new-session -s pfsense ./parte3/start-pfsense.sh

# Terminal 2: atacante (Alpine 3.20, 192.168.10.10)
nix develop .#parte3 -c tmux new-session -s attacker ./parte3/start-attacker.sh

# Terminal 3: objetivo (Alpine 3.20, 192.168.20.10, HTTP en :80)
nix develop .#parte3 -c tmux new-session -s target ./parte3/start-target.sh
```

En el atacante:

```sh
root
ip link set eth0 up
ip addr add 192.168.10.10/24 dev eth0
ip link set eth1 up
udhcpc -i eth1 -q -n
ip route add 192.168.20.0/24 via 192.168.10.1 dev eth0
apk update && apk add nmap
```

En el objetivo:

```sh
root
ip link set eth0 up
ip addr add 192.168.20.10/24 dev eth0
ip route add default via 192.168.20.1
mkdir -p /var/www
echo "Servidor interno A4-P3" > /var/www/index.html
while true; do printf "HTTP/1.1 200 OK\r\nContent-Length: 23\r\n\r\nServidor interno A4-P3\n" | nc -l -p 80; done &
```

## Configuración de pfSense

La GUI se configura de forma reproducible con:

```sh
nix develop .#screenshots -c python3 parte3/setup-gui.py
```

El script crea los alias `VLAN_INTERNA` y `VLAN_NO_CONFIABLE`, las tres reglas
de OPT1, añade la interfaz de Snort, instala la regla personalizada, arranca
Snort y aplica la lista de DNS sinkhole de Unbound. Es idempotente.

Reglas de OPT1, en este orden:

1. `pass  tcp        any  -> VLAN_INTERNA  80` — único acceso permitido.
2. `pass  tcp/udp    any  -> This Firewall 53` — resolver para filtrado DNS.
3. `block any        any  -> VLAN_INTERNA  any` — bloqueo con registro.

La regla de Snort está en `snort-custom.rules` (SID `1000001`): dispara una
alerta cuando un mismo origen envía 15 SYN en 5 segundos contra `$HOME_NET`.
El bloqueo de ofensores está activado, pero la *pass list* por defecto excluye
las redes locales, por lo que en este laboratorio la validación es de
**detección (IDS)**; el bloqueo de accesos a la VLAN interna lo hace PF.

`unbound-phishing.conf` contiene las zonas `always_nxdomain` para dominios de
phishing de prueba. Antes de aplicarlas se comprobó que `phishing.test`
resolvía a `192.168.20.10` mediante `local-data`; después devuelve NXDOMAIN.

## Validación

```sh
# Desde el atacante (eth0 = 192.168.10.10)
nmap -Pn -sS -T4 -p 1-200 192.168.20.10
wget -qO- -T 4 http://192.168.20.10/
nslookup phishing.test 192.168.10.1
```

Resultados esperados:

- `80/tcp open`, 199 puertos `filtered` (regla `block` de PF).
- `Servidor interno A4-P3` (regla `pass` de PF).
- `NXDOMAIN` para los dominios de phishing (Unbound).

Evidencia: `parte3/evidence/` y las capturas `docs/screenshots/07` a `13`.
