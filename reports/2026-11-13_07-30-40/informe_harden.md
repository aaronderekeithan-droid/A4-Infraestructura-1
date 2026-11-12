# Informe de hardening CIS (modo harden)

- Fecha: 2026-11-13_07-30-40
- Benchmark: CIS Cisco IOS 15 v4.1.1
- Estudiante: Aaron Hernandez (2025-0800)

## Resumen

| Equipo | Antes | Despues |
|---|---|---|
| R1 | 19/19 (100 %) | 19/19 (100 %) |
| SW1 | 19/19 (100 %) | 19/19 (100 %) |

## R1

| ID CIS | Control | Antes | Despues | Por que | Evidencia (despues) |
|---|---|---|---|---|---|
| 1.2.2 | Set 'transport input ssh' for 'line vty' | CUMPLE | CUMPLE | Telnet envia usuario y clave en texto plano; solo SSH cifra la sesion de administracion. | line vty 0 4: transport input ssh |
| 1.2.4 | Create 'access-list' for use with 'line vty' | CUMPLE | CUMPLE | Define quien puede administrar el equipo: solo la estacion ADMIN. | VTY-ACL: permit 10.8.25.10 / deny   any log |
| 1.2.5 | Set 'access-class' for 'line vty' | CUMPLE | CUMPLE | Sin access-class, cualquier host de la red puede intentar entrar por vty. | line vty 0 4: access-class VTY-ACL in |
| - | Set 'exec-timeout' <= 10 min en 'line con 0' y 'line vty' (ID por confirmar en el PDF) | CUMPLE | CUMPLE | Cierra sesiones abandonadas; una sesion privilegiada olvidada es una puerta abierta. | line con 0: exec-timeout 5 0; line vty 0 4: exec-timeout 5 0 |
| 1.3.1 | Set the 'banner-text' for 'banner exec' | CUMPLE | CUMPLE | Aviso de uso autorizado al abrir una sesion EXEC; sirve como respaldo ante accesos indebidos. | banner exec configurado |
| 1.3.2 | Set the 'banner-text' for 'banner login' | CUMPLE | CUMPLE | Aviso legal de acceso restringido antes de autenticarse. | banner login configurado |
| 1.3.3 | Set the 'banner-text' for 'banner motd' | CUMPLE | CUMPLE | Mensaje del dia: recuerda que el equipo es de uso controlado. | banner motd configurado |
| 1.4.1 | Set 'password' for 'enable secret' | CUMPLE | CUMPLE | enable secret guarda un hash; 'enable password' queda legible en la configuracion. | enable secret presente |
| 1.4.2 | Enable 'service password-encryption' | CUMPLE | CUMPLE | Cifra las claves en la configuracion para que no se lean a simple vista. | service password-encryption activo |
| 1.5.2 | Unset private for 'snmp-server community' | CUMPLE | CUMPLE | 'private' es una comunidad por defecto conocida por cualquier atacante. | sin comunidad 'private' |
| 1.5.3 | Unset public for 'snmp-server community' | CUMPLE | CUMPLE | 'public' es una comunidad por defecto conocida por cualquier atacante. | sin comunidad 'public' |
| 1.5.4 | Do not set 'RW' for any 'snmp-server community' | CUMPLE | CUMPLE | Una comunidad de escritura permite modificar el equipo por SNMP. | sin comunidades RW |
| 2.1.1.1.4 | Set 'seconds' for 'ip ssh timeout' | CUMPLE | CUMPLE | Limita el tiempo para autenticarse por SSH y reduce conexiones colgadas y fuerza bruta. | ip ssh time-out 60 |
| 2.1.2 | Set 'no cdp run' | CUMPLE | CUMPLE | CDP revela modelo, version e IP a cualquier vecino; no se usa en este laboratorio. | CDP deshabilitado |
| 2.1.3 | Set 'no ip bootp server' | CUMPLE | CUMPLE | BOOTP es un servicio innecesario que amplia la superficie de ataque. | BOOTP deshabilitado |
| 2.1.4 | Set 'no service dhcp' | CUMPLE | CUMPLE | El equipo no es servidor DHCP en esta topologia; el servicio se apaga. | service dhcp deshabilitado |
| 2.1.8 | Set 'no service pad' | CUMPLE | CUMPLE | PAD es un servicio heredado sin uso. | service pad deshabilitado |
| 2.2.4 | Set IP address for 'logging host' | CUMPLE | CUMPLE | Centraliza los logs en ADMIN: la evidencia queda fuera del equipo. | logging host 10.8.25.10 |
| - | Set 'no ip http server' (ID por confirmar en el PDF) | CUMPLE | CUMPLE | El servidor HTTP del router va en claro y amplia la superficie de ataque. | servidor HTTP deshabilitado |

## SW1

| ID CIS | Control | Antes | Despues | Por que | Evidencia (despues) |
|---|---|---|---|---|---|
| 1.2.2 | Set 'transport input ssh' for 'line vty' | CUMPLE | CUMPLE | Telnet envia usuario y clave en texto plano; solo SSH cifra la sesion de administracion. | line vty 0 4: transport input ssh |
| 1.2.4 | Create 'access-list' for use with 'line vty' | CUMPLE | CUMPLE | Define quien puede administrar el equipo: solo la estacion ADMIN. | VTY-ACL: permit 10.8.25.10 / deny   any log |
| 1.2.5 | Set 'access-class' for 'line vty' | CUMPLE | CUMPLE | Sin access-class, cualquier host de la red puede intentar entrar por vty. | line vty 0 4: access-class VTY-ACL in |
| - | Set 'exec-timeout' <= 10 min en 'line con 0' y 'line vty' (ID por confirmar en el PDF) | CUMPLE | CUMPLE | Cierra sesiones abandonadas; una sesion privilegiada olvidada es una puerta abierta. | line con 0: exec-timeout 5 0; line vty 0 4: exec-timeout 5 0 |
| 1.3.1 | Set the 'banner-text' for 'banner exec' | CUMPLE | CUMPLE | Aviso de uso autorizado al abrir una sesion EXEC; sirve como respaldo ante accesos indebidos. | banner exec configurado |
| 1.3.2 | Set the 'banner-text' for 'banner login' | CUMPLE | CUMPLE | Aviso legal de acceso restringido antes de autenticarse. | banner login configurado |
| 1.3.3 | Set the 'banner-text' for 'banner motd' | CUMPLE | CUMPLE | Mensaje del dia: recuerda que el equipo es de uso controlado. | banner motd configurado |
| 1.4.1 | Set 'password' for 'enable secret' | CUMPLE | CUMPLE | enable secret guarda un hash; 'enable password' queda legible en la configuracion. | enable secret presente |
| 1.4.2 | Enable 'service password-encryption' | CUMPLE | CUMPLE | Cifra las claves en la configuracion para que no se lean a simple vista. | service password-encryption activo |
| 1.5.2 | Unset private for 'snmp-server community' | CUMPLE | CUMPLE | 'private' es una comunidad por defecto conocida por cualquier atacante. | sin comunidad 'private' |
| 1.5.3 | Unset public for 'snmp-server community' | CUMPLE | CUMPLE | 'public' es una comunidad por defecto conocida por cualquier atacante. | sin comunidad 'public' |
| 1.5.4 | Do not set 'RW' for any 'snmp-server community' | CUMPLE | CUMPLE | Una comunidad de escritura permite modificar el equipo por SNMP. | sin comunidades RW |
| 2.1.1.1.4 | Set 'seconds' for 'ip ssh timeout' | CUMPLE | CUMPLE | Limita el tiempo para autenticarse por SSH y reduce conexiones colgadas y fuerza bruta. | ip ssh time-out 60 |
| 2.1.2 | Set 'no cdp run' | CUMPLE | CUMPLE | CDP revela modelo, version e IP a cualquier vecino; no se usa en este laboratorio. | CDP deshabilitado |
| 2.1.3 | Set 'no ip bootp server' | CUMPLE | CUMPLE | BOOTP es un servicio innecesario que amplia la superficie de ataque. | BOOTP deshabilitado |
| 2.1.4 | Set 'no service dhcp' | CUMPLE | CUMPLE | El equipo no es servidor DHCP en esta topologia; el servicio se apaga. | service dhcp deshabilitado |
| 2.1.8 | Set 'no service pad' | CUMPLE | CUMPLE | PAD es un servicio heredado sin uso. | service pad deshabilitado |
| 2.2.4 | Set IP address for 'logging host' | CUMPLE | CUMPLE | Centraliza los logs en ADMIN: la evidencia queda fuera del equipo. | logging host 10.8.25.10 |
| - | Set 'no ip http server' (ID por confirmar en el PDF) | CUMPLE | CUMPLE | El servidor HTTP del router va en claro y amplia la superficie de ataque. | servidor HTTP deshabilitado |

N/A = el equipo no soporta el comando; no cuenta para el porcentaje.
