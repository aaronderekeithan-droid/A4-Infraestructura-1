# Informe de auditoria CIS (modo audit, sin cambios)

- Fecha: 2026-11-14_04-46-11
- Benchmark: CIS Cisco IOS 15 v4.1.1 (R1, SW1) y CIS FortiGate (FW1)
- Estudiante: Aaron Hernandez (2025-0800)

## Resumen

| Equipo | Cumple | Total | % |
|---|---|---|---|
| R1 | 0 | 19 | 0 % |
| SW1 | 2 | 19 | 10 % |
| FW1 | 0 | 7 | 0 % |

## R1

| ID CIS | Control | Estado | Evidencia | Por que |
|---|---|---|---|---|
| 1.2.2 | Set 'transport input ssh' for 'line vty' | NO CUMPLE | line vty 0 4: transport input all | Telnet envia usuario y clave en texto plano; solo SSH cifra la sesion de administracion. |
| 1.2.4 | Create 'access-list' for use with 'line vty' | NO CUMPLE | no existe la ACL VTY-ACL | Define quien puede administrar el equipo: solo la estacion ADMIN. |
| 1.2.5 | Set 'access-class' for 'line vty' | NO CUMPLE | line vty 0 4: sin access-class | Sin access-class, cualquier host de la red puede intentar entrar por vty. |
| - | Set 'exec-timeout' <= 10 min en 'line con 0' y 'line vty' (ID por confirmar en el PDF) | NO CUMPLE | line con 0: exec-timeout 0 0; line vty 0 4: exec-timeout 0 0 | Cierra sesiones abandonadas; una sesion privilegiada olvidada es una puerta abierta. |
| 1.3.1 | Set the 'banner-text' for 'banner exec' | NO CUMPLE | sin banner exec | Aviso de uso autorizado al abrir una sesion EXEC; sirve como respaldo ante accesos indebidos. |
| 1.3.2 | Set the 'banner-text' for 'banner login' | NO CUMPLE | sin banner login | Aviso legal de acceso restringido antes de autenticarse. |
| 1.3.3 | Set the 'banner-text' for 'banner motd' | NO CUMPLE | sin banner motd | Mensaje del dia: recuerda que el equipo es de uso controlado. |
| 1.4.1 | Set 'password' for 'enable secret' | NO CUMPLE | sin enable secret; enable password en uso | enable secret guarda un hash; 'enable password' queda legible en la configuracion. |
| 1.4.2 | Enable 'service password-encryption' | NO CUMPLE | no service password-encryption | Cifra las claves en la configuracion para que no se lean a simple vista. |
| 1.5.2 | Unset private for 'snmp-server community' | NO CUMPLE | comunidad 'private' presente | 'private' es una comunidad por defecto conocida por cualquier atacante. |
| 1.5.3 | Unset public for 'snmp-server community' | NO CUMPLE | comunidad 'public' presente | 'public' es una comunidad por defecto conocida por cualquier atacante. |
| 1.5.4 | Do not set 'RW' for any 'snmp-server community' | NO CUMPLE | comunidades RW: private | Una comunidad de escritura permite modificar el equipo por SNMP. |
| 2.1.1.1.4 | Set 'seconds' for 'ip ssh timeout' | NO CUMPLE | ip ssh time-out no configurado (por defecto 120 s) | Limita el tiempo para autenticarse por SSH y reduce conexiones colgadas y fuerza bruta. |
| 2.1.2 | Set 'no cdp run' | NO CUMPLE | CDP activo | CDP revela modelo, version e IP a cualquier vecino; no se usa en este laboratorio. |
| 2.1.3 | Set 'no ip bootp server' | NO CUMPLE | ip bootp server activo | BOOTP es un servicio innecesario que amplia la superficie de ataque. |
| 2.1.4 | Set 'no service dhcp' | NO CUMPLE | service dhcp activo | El equipo no es servidor DHCP en esta topologia; el servicio se apaga. |
| 2.1.8 | Set 'no service pad' | NO CUMPLE | service pad activo | PAD es un servicio heredado sin uso. |
| 2.2.4 | Set IP address for 'logging host' | NO CUMPLE | sin servidor de logs remoto | Centraliza los logs en ADMIN: la evidencia queda fuera del equipo. |
| - | Set 'no ip http server' (ID por confirmar en el PDF) | NO CUMPLE | activo: ip http server | El servidor HTTP del router va en claro y amplia la superficie de ataque. |

## SW1

| ID CIS | Control | Estado | Evidencia | Por que |
|---|---|---|---|---|
| 1.2.2 | Set 'transport input ssh' for 'line vty' | NO CUMPLE | line vty 0 4: transport input all | Telnet envia usuario y clave en texto plano; solo SSH cifra la sesion de administracion. |
| 1.2.4 | Create 'access-list' for use with 'line vty' | NO CUMPLE | no existe la ACL VTY-ACL | Define quien puede administrar el equipo: solo la estacion ADMIN. |
| 1.2.5 | Set 'access-class' for 'line vty' | NO CUMPLE | line vty 0 4: sin access-class | Sin access-class, cualquier host de la red puede intentar entrar por vty. |
| - | Set 'exec-timeout' <= 10 min en 'line con 0' y 'line vty' (ID por confirmar en el PDF) | NO CUMPLE | line con 0: exec-timeout 0 0; line vty 0 4: exec-timeout 0 0 | Cierra sesiones abandonadas; una sesion privilegiada olvidada es una puerta abierta. |
| 1.3.1 | Set the 'banner-text' for 'banner exec' | NO CUMPLE | sin banner exec | Aviso de uso autorizado al abrir una sesion EXEC; sirve como respaldo ante accesos indebidos. |
| 1.3.2 | Set the 'banner-text' for 'banner login' | NO CUMPLE | sin banner login | Aviso legal de acceso restringido antes de autenticarse. |
| 1.3.3 | Set the 'banner-text' for 'banner motd' | NO CUMPLE | sin banner motd | Mensaje del dia: recuerda que el equipo es de uso controlado. |
| 1.4.1 | Set 'password' for 'enable secret' | NO CUMPLE | sin enable secret; enable password en uso | enable secret guarda un hash; 'enable password' queda legible en la configuracion. |
| 1.4.2 | Enable 'service password-encryption' | NO CUMPLE | no service password-encryption | Cifra las claves en la configuracion para que no se lean a simple vista. |
| 1.5.2 | Unset private for 'snmp-server community' | CUMPLE | sin comunidad 'private' | 'private' es una comunidad por defecto conocida por cualquier atacante. |
| 1.5.3 | Unset public for 'snmp-server community' | NO CUMPLE | comunidad 'public' presente | 'public' es una comunidad por defecto conocida por cualquier atacante. |
| 1.5.4 | Do not set 'RW' for any 'snmp-server community' | CUMPLE | sin comunidades RW | Una comunidad de escritura permite modificar el equipo por SNMP. |
| 2.1.1.1.4 | Set 'seconds' for 'ip ssh timeout' | NO CUMPLE | ip ssh time-out no configurado (por defecto 120 s) | Limita el tiempo para autenticarse por SSH y reduce conexiones colgadas y fuerza bruta. |
| 2.1.2 | Set 'no cdp run' | NO CUMPLE | CDP activo | CDP revela modelo, version e IP a cualquier vecino; no se usa en este laboratorio. |
| 2.1.3 | Set 'no ip bootp server' | NO CUMPLE | ip bootp server activo | BOOTP es un servicio innecesario que amplia la superficie de ataque. |
| 2.1.4 | Set 'no service dhcp' | NO CUMPLE | service dhcp activo | El equipo no es servidor DHCP en esta topologia; el servicio se apaga. |
| 2.1.8 | Set 'no service pad' | NO CUMPLE | service pad activo | PAD es un servicio heredado sin uso. |
| 2.2.4 | Set IP address for 'logging host' | NO CUMPLE | sin servidor de logs remoto | Centraliza los logs en ADMIN: la evidencia queda fuera del equipo. |
| - | Set 'no ip http server' (ID por confirmar en el PDF) | NO CUMPLE | activo: ip http server | El servidor HTTP del router va en claro y amplia la superficie de ataque. |

## FW1

| ID CIS | Control | Estado | Evidencia | Por que |
|---|---|---|---|---|
| - | Disable insecure management protocols (HTTP, Telnet) on interfaces | NO CUMPLE | port1: ping https ssh http telnet; fortilink: ping fabric | HTTP y Telnet administran el firewall en texto plano; solo HTTPS y SSH cifran la sesion. |
| - | Set 'admintimeout' to 5 minutes or less | NO CUMPLE | admintimeout 60 min | Cierra sesiones de administracion abandonadas. |
| - | Enable password policy (length 8, upper, lower, number, special) | NO CUMPLE | password-policy status disable; por debajo del minimo: min-lower-case-letter=0, min-upper-case-letter=0, min-number=0, min-non-alphanumeric=0 | Evita claves de administrador debiles. |
| - | Restrict administrator access with 'trusthost' | NO CUMPLE | admin: trusthost1 0.0.0.0 0.0.0.0 | Solo la estacion ADMIN puede iniciar sesion como administrador. |
| - | Enable remote logging to a syslog server | NO CUMPLE | syslogd disable, servidor - | Los logs quedan en ADMIN, fuera del equipo, como evidencia. |
| - | Disable USB auto-install of configuration and firmware | NO CUMPLE | auto-install-config enable, auto-install-image enable | Evita que alguien con acceso fisico cargue configuracion o firmware desde un USB. |
| - | Disable TLS 1.0/1.1 for the HTTPS administrative interface | NO CUMPLE | admin-https-ssl-versions tlsv1-1 tlsv1-2 | Las versiones TLS antiguas tienen debilidades conocidas. |
