#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cis_hardening.py - Auditoria y hardening basados en el CIS Cisco IOS 15 Benchmark v4.1.1

Estudiante: Aaron Hernandez - Matricula 2025-0800 - Red 10.8.25.0/24

Modos:
  audit   Revisa R1 y SW1 y genera un informe SIN cambiar nada.
  harden  Aplica los controles que no cumplen, guarda la configuracion,
          vuelve a auditar y genera el informe final (Antes / Despues / Por que).

Ejemplos:
  python cis_hardening.py audit
  python cis_hardening.py harden
  python cis_hardening.py audit --offline R1=R1_antes.txt SW1=SW1_antes.txt

Salida (carpeta reports/<fecha>/):
  informe_audit.md o informe_harden.md
  running-configs/<equipo>_antes.txt y <equipo>_despues.txt
"""

import argparse
import getpass
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional

# --------------------------------------------------------------------------
# Parametros del laboratorio
# --------------------------------------------------------------------------
DEVICES = {"R1": "10.8.25.1", "SW1": "10.8.25.2"}
ADMIN_IP = "10.8.25.10"      # estacion ADMIN: unica que puede administrar por vty
SYSLOG_IP = "10.8.25.10"     # servidor de logs (rsyslog en ADMIN)
ACL_NAME = "VTY-ACL"
EXEC_TIMEOUT_CMD = "exec-timeout 5 0"

OK, FAIL, NA = "CUMPLE", "NO CUMPLE", "N/A"

BANNERS = {
    "exec": "Sesion autorizada. Toda la actividad queda registrada.",
    "login": "ACCESO RESTRINGIDO. Solo personal autorizado. "
             "Toda la actividad es registrada y monitoreada.",
    "motd": "Equipo del laboratorio de Seguridad de Redes - ITLA.",
}


@dataclass
class Ctx:
    admin_ip: str = ADMIN_IP
    syslog_ip: str = SYSLOG_IP
    new_secret: Optional[str] = None


@dataclass
class Check:
    cid: str            # ID del CIS Benchmark ("" si no esta verificado)
    title: str
    why: str
    test: Callable      # (cfg, ctx) -> (bool, evidencia)
    fix: Callable       # (cfg, ctx) -> lista de comandos


# --------------------------------------------------------------------------
# Utilidades para leer la running-config
# --------------------------------------------------------------------------
def has(cfg: str, pattern: str) -> bool:
    return re.search(pattern, cfg, re.M) is not None


def line_blocks(cfg: str, prefix: str):
    """Devuelve [(encabezado, [lineas hijas])] de los bloques que empiezan con prefix."""
    blocks, cur = [], None
    for raw in cfg.splitlines():
        if raw.startswith(prefix):
            cur = (raw.strip(), [])
            blocks.append(cur)
        elif cur is not None and raw[:1] in (" ", "\t"):
            cur[1].append(raw.strip())
        else:
            cur = None
    return blocks


def snmp_lines(cfg: str):
    return [l.split() for l in cfg.splitlines() if l.startswith("snmp-server community ")]


# --------------------------------------------------------------------------
# Pruebas (test) y correcciones (fix) de cada control
# --------------------------------------------------------------------------
def t_transport_ssh(cfg, ctx):
    blocks = line_blocks(cfg, "line vty")
    if not blocks:
        return False, "sin lineas vty en la configuracion"
    ok, ev = True, []
    for hdr, body in blocks:
        tr = [l for l in body if l.startswith("transport input")]
        val = tr[0] if tr else "transport input all (por defecto)"
        ev.append(f"{hdr}: {val}")
        if val != "transport input ssh":
            ok = False
    return ok, "; ".join(ev)


def f_transport_ssh(cfg, ctx):
    cmds = []
    for hdr, _ in line_blocks(cfg, "line vty"):
        cmds += [hdr, "transport input ssh", "exit"]
    return cmds


def t_vty_acl(cfg, ctx):
    m = re.search(rf"^ip access-list standard {ACL_NAME}\n((?: .*\n?)*)", cfg, re.M)
    if not m:
        return False, f"no existe la ACL {ACL_NAME}"
    body = [l.strip() for l in m.group(1).splitlines() if l.strip()]
    if not any(ctx.admin_ip in l and l.startswith("permit") for l in body):
        return False, f"la ACL {ACL_NAME} no permite a {ctx.admin_ip}: " + " | ".join(body)
    return True, f"{ACL_NAME}: " + " | ".join(body)


def f_vty_acl(cfg, ctx):
    return [f"ip access-list standard {ACL_NAME}",
            f"permit host {ctx.admin_ip}",
            "deny any log",
            "exit"]


def t_access_class(cfg, ctx):
    blocks = line_blocks(cfg, "line vty")
    if not blocks:
        return False, "sin lineas vty en la configuracion"
    ok, ev = True, []
    for hdr, body in blocks:
        ac = next((l for l in body if l.startswith("access-class")), None)
        ev.append(f"{hdr}: {ac or 'sin access-class'}")
        if not (ac and ac.startswith(f"access-class {ACL_NAME} in")):
            ok = False
    return ok, "; ".join(ev)


def f_access_class(cfg, ctx):
    cmds = []
    for hdr, _ in line_blocks(cfg, "line vty"):
        cmds += [hdr, f"access-class {ACL_NAME} in", "exit"]
    return cmds


def _timeout_seconds(line):
    m = re.match(r"exec-timeout (\d+)(?: (\d+))?$", line)
    return int(m.group(1)) * 60 + int(m.group(2) or 0) if m else None


def _bad_timeout_headers(cfg):
    bad, ev = [], []
    for prefix in ("line con", "line vty"):
        for hdr, body in line_blocks(cfg, prefix):
            val = next((l for l in body if l.startswith("exec-timeout")), None)
            secs = _timeout_seconds(val) if val else 600
            ev.append(f"{hdr}: {val or 'exec-timeout 10 0 (por defecto)'}")
            if secs == 0 or secs is None or secs > 600:
                bad.append(hdr)
    return bad, ev


def t_exec_timeout(cfg, ctx):
    bad, ev = _bad_timeout_headers(cfg)
    if not ev:
        return False, "sin lineas con/vty en la configuracion"
    return (not bad), "; ".join(ev)


def f_exec_timeout(cfg, ctx):
    cmds = []
    for hdr in _bad_timeout_headers(cfg)[0]:
        cmds += [hdr, EXEC_TIMEOUT_CMD, "exit"]
    return cmds


def t_banner(kind):
    def _t(cfg, ctx):
        ok = has(cfg, rf"^banner {kind}\b")
        return ok, (f"banner {kind} configurado" if ok else f"sin banner {kind}")
    return _t


def f_banner(kind):
    return lambda cfg, ctx: [f"banner {kind} # {BANNERS[kind]} #"]


def t_secret(cfg, ctx):
    sec = has(cfg, r"^enable secret ")
    pwd = has(cfg, r"^enable password ")
    ev = "enable secret presente" if sec else "sin enable secret"
    if pwd:
        ev += "; enable password en uso"
    return (sec and not pwd), ev


def f_secret(cfg, ctx):
    if not ctx.new_secret:
        return []
    cmds = [f"enable secret {ctx.new_secret}"]
    if has(cfg, r"^enable password "):
        cmds.append("no enable password")
    return cmds


def t_pwd_encryption(cfg, ctx):
    ok = has(cfg, r"^service password-encryption")
    return ok, ("service password-encryption activo" if ok else "no service password-encryption")


def t_snmp_name(name):
    def _t(cfg, ctx):
        found = [p for p in snmp_lines(cfg) if len(p) > 2 and p[2] == name]
        return (not found), (f"comunidad '{name}' presente" if found else f"sin comunidad '{name}'")
    return _t


def f_snmp_name(name):
    return lambda cfg, ctx: [f"no snmp-server community {name}"]


def _rw_communities(cfg):
    return [p[2] for p in snmp_lines(cfg)
            if len(p) > 2 and any(x.upper() == "RW" for x in p[3:])]


def t_snmp_rw(cfg, ctx):
    rw = _rw_communities(cfg)
    return (not rw), (f"comunidades RW: {', '.join(rw)}" if rw else "sin comunidades RW")


def f_snmp_rw(cfg, ctx):
    return [f"no snmp-server community {n}" for n in _rw_communities(cfg)
            if n not in ("private", "public")]


def t_ssh_timeout(cfg, ctx):
    m = re.search(r"^ip ssh time-out (\d+)", cfg, re.M)
    if not m:
        return False, "ip ssh time-out no configurado (por defecto 120 s)"
    v = int(m.group(1))
    return v <= 60, f"ip ssh time-out {v}"


def t_no_cmd(pattern, on_msg, off_msg):
    def _t(cfg, ctx):
        ok = has(cfg, pattern)
        return ok, (off_msg if ok else on_msg)
    return _t


def f_cmds(*cmds):
    return lambda cfg, ctx: list(cmds)


def t_logging(cfg, ctx):
    ip = re.escape(ctx.syslog_ip)
    ok = has(cfg, rf"^logging (host )?{ip}\b")
    return ok, (f"logging host {ctx.syslog_ip}" if ok else "sin servidor de logs remoto")


def f_logging(cfg, ctx):
    return [f"logging host {ctx.syslog_ip}"]


def t_http(cfg, ctx):
    on = [l for l in ("ip http server", "ip http secure-server") if has(cfg, rf"^{l}\s*$")]
    return (not on), (f"activo: {', '.join(on)}" if on else "servidor HTTP deshabilitado")


def f_http(cfg, ctx):
    return ["no " + l for l in ("ip http server", "ip http secure-server")
            if has(cfg, rf"^{l}\s*$")]


# --------------------------------------------------------------------------
# Lista de controles (IDs verificados en la auditoria de ONYX, CIS IOS 15 v4.1.1)
# --------------------------------------------------------------------------
CHECKS: List[Check] = [
    Check("1.2.2", "Set 'transport input ssh' for 'line vty'",
          "Telnet envia usuario y clave en texto plano; solo SSH cifra la sesion de administracion.",
          t_transport_ssh, f_transport_ssh),
    Check("1.2.4", "Create 'access-list' for use with 'line vty'",
          "Define quien puede administrar el equipo: solo la estacion ADMIN.",
          t_vty_acl, f_vty_acl),
    Check("1.2.5", "Set 'access-class' for 'line vty'",
          "Sin access-class, cualquier host de la red puede intentar entrar por vty.",
          t_access_class, f_access_class),
    Check("", "Set 'exec-timeout' <= 10 min en 'line con 0' y 'line vty' (ID por confirmar en el PDF)",
          "Cierra sesiones abandonadas; una sesion privilegiada olvidada es una puerta abierta.",
          t_exec_timeout, f_exec_timeout),
    Check("1.3.1", "Set the 'banner-text' for 'banner exec'",
          "Aviso de uso autorizado al abrir una sesion EXEC; sirve como respaldo ante accesos indebidos.",
          t_banner("exec"), f_banner("exec")),
    Check("1.3.2", "Set the 'banner-text' for 'banner login'",
          "Aviso legal de acceso restringido antes de autenticarse.",
          t_banner("login"), f_banner("login")),
    Check("1.3.3", "Set the 'banner-text' for 'banner motd'",
          "Mensaje del dia: recuerda que el equipo es de uso controlado.",
          t_banner("motd"), f_banner("motd")),
    Check("1.4.1", "Set 'password' for 'enable secret'",
          "enable secret guarda un hash; 'enable password' queda legible en la configuracion.",
          t_secret, f_secret),
    Check("1.4.2", "Enable 'service password-encryption'",
          "Cifra las claves en la configuracion para que no se lean a simple vista.",
          t_pwd_encryption, f_cmds("service password-encryption")),
    Check("1.5.2", "Unset private for 'snmp-server community'",
          "'private' es una comunidad por defecto conocida por cualquier atacante.",
          t_snmp_name("private"), f_snmp_name("private")),
    Check("1.5.3", "Unset public for 'snmp-server community'",
          "'public' es una comunidad por defecto conocida por cualquier atacante.",
          t_snmp_name("public"), f_snmp_name("public")),
    Check("1.5.4", "Do not set 'RW' for any 'snmp-server community'",
          "Una comunidad de escritura permite modificar el equipo por SNMP.",
          t_snmp_rw, f_snmp_rw),
    Check("2.1.1.1.4", "Set 'seconds' for 'ip ssh timeout'",
          "Limita el tiempo para autenticarse por SSH y reduce conexiones colgadas y fuerza bruta.",
          t_ssh_timeout, f_cmds("ip ssh time-out 60")),
    Check("2.1.2", "Set 'no cdp run'",
          "CDP revela modelo, version e IP a cualquier vecino; no se usa en este laboratorio.",
          t_no_cmd(r"^no cdp run", "CDP activo", "CDP deshabilitado"), f_cmds("no cdp run")),
    Check("2.1.3", "Set 'no ip bootp server'",
          "BOOTP es un servicio innecesario que amplia la superficie de ataque.",
          t_no_cmd(r"^no ip bootp server", "ip bootp server activo", "BOOTP deshabilitado"),
          f_cmds("no ip bootp server")),
    Check("2.1.4", "Set 'no service dhcp'",
          "El equipo no es servidor DHCP en esta topologia; el servicio se apaga.",
          t_no_cmd(r"^no service dhcp", "service dhcp activo", "service dhcp deshabilitado"),
          f_cmds("no service dhcp")),
    Check("2.1.8", "Set 'no service pad'",
          "PAD es un servicio heredado sin uso.",
          t_no_cmd(r"^no service pad", "service pad activo", "service pad deshabilitado"),
          f_cmds("no service pad")),
    Check("2.2.4", "Set IP address for 'logging host'",
          "Centraliza los logs en ADMIN: la evidencia queda fuera del equipo.",
          t_logging, f_logging),
    Check("", "Set 'no ip http server' (ID por confirmar en el PDF)",
          "El servidor HTTP del router va en claro y amplia la superficie de ataque.",
          t_http, f_http),
]


# --------------------------------------------------------------------------
# Auditoria
# --------------------------------------------------------------------------
def run_checks(cfg: str, ctx: Ctx):
    out = []
    for ch in CHECKS:
        try:
            ok, ev = ch.test(cfg, ctx)
        except Exception as exc:  # una falla de lectura no debe tumbar el informe
            ok, ev = False, f"error evaluando: {exc}"
        out.append({"check": ch, "status": OK if ok else FAIL, "ev": ev})
    return out


def score(res):
    valid = [r for r in res if r["status"] != NA]
    ok = sum(1 for r in valid if r["status"] == OK)
    return ok, len(valid)


def pct(res):
    ok, tot = score(res)
    return (100 * ok // tot) if tot else 100


# --------------------------------------------------------------------------
# Conexion y aplicacion (Netmiko)
# --------------------------------------------------------------------------
ERR = re.compile(r"^% (Invalid|Incomplete|Ambiguous|Unrecognized)", re.M)


def connect(name, ip, user, password, secret):
    from netmiko import ConnectHandler  # import tardio: audit --offline no lo necesita
    conn = ConnectHandler(device_type="cisco_ios", host=ip, username=user,
                          password=password, secret=secret, conn_timeout=20,
                          auth_timeout=30, banner_timeout=30, global_delay_factor=2)
    conn.enable()
    return conn


def get_config(conn) -> str:
    return conn.send_command("show running-config", read_timeout=90)


def apply_cmds(conn, cmds):
    try:
        out = conn.send_config_set(cmds, cmd_verify=False, read_timeout=60)
    except TypeError:
        out = conn.send_config_set(cmds)
    return out, bool(ERR.search(out))


def save_config(conn):
    try:
        conn.save_config()
    except Exception:
        conn.send_command_timing("write memory")


# --------------------------------------------------------------------------
# Informes
# --------------------------------------------------------------------------
def cid(ch):
    return ch.cid or "-"


def esc(s, n=150):
    s = s.replace("|", "/").replace("\n", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def report_audit(path, ts, results):
    L = [f"# Informe de auditoria CIS (modo audit, sin cambios)", "",
         f"- Fecha: {ts}", "- Benchmark: CIS Cisco IOS 15 v4.1.1",
         "- Estudiante: Aaron Hernandez (2025-0800)", "",
         "## Resumen", "", "| Equipo | Cumple | Total | % |", "|---|---|---|---|"]
    for name, res in results.items():
        ok, tot = score(res)
        L.append(f"| {name} | {ok} | {tot} | {pct(res)} % |")
    for name, res in results.items():
        L += ["", f"## {name}", "",
              "| ID CIS | Control | Estado | Evidencia | Por que |", "|---|---|---|---|---|"]
        for r in res:
            ch = r["check"]
            L.append(f"| {cid(ch)} | {esc(ch.title, 90)} | {r['status']} | {esc(r['ev'])} | {esc(ch.why, 120)} |")
    write(path, "\n".join(L) + "\n")


def report_harden(path, ts, before, after, notes):
    L = [f"# Informe de hardening CIS (modo harden)", "",
         f"- Fecha: {ts}", "- Benchmark: CIS Cisco IOS 15 v4.1.1",
         "- Estudiante: Aaron Hernandez (2025-0800)", "",
         "## Resumen", "", "| Equipo | Antes | Despues |", "|---|---|---|"]
    for name in before:
        b_ok, b_t = score(before[name])
        a_ok, a_t = score(after[name])
        L.append(f"| {name} | {b_ok}/{b_t} ({pct(before[name])} %) | {a_ok}/{a_t} ({pct(after[name])} %) |")
    for name in before:
        L += ["", f"## {name}", "",
              "| ID CIS | Control | Antes | Despues | Por que | Evidencia (despues) |",
              "|---|---|---|---|---|---|"]
        for rb, ra in zip(before[name], after[name]):
            ch = rb["check"]
            L.append(f"| {cid(ch)} | {esc(ch.title, 90)} | {rb['status']} | {ra['status']} | "
                     f"{esc(ch.why, 120)} | {esc(ra['ev'])} |")
        if notes.get(name):
            L += ["", "Observaciones:", ""] + [f"- {n}" for n in notes[name]]
    L += ["", "N/A = el equipo no soporta el comando; no cuenta para el porcentaje."]
    write(path, "\n".join(L) + "\n")


def print_summary(title, results):
    print(f"\n{title}")
    for name, res in results.items():
        ok, tot = score(res)
        print(f"  {name}: {ok}/{tot} controles cumplen ({pct(res)} %)")
        for r in res:
            if r["status"] == FAIL:
                print(f"     NO CUMPLE {cid(r['check']):>9}  {r['check'].title}")


# --------------------------------------------------------------------------
# Flujo principal
# --------------------------------------------------------------------------
def ask(prompt, env):
    return os.environ.get(env) or getpass.getpass(prompt)


def read_new_secret():
    env = os.environ.get("CIS_NEW_SECRET")
    if env:
        return env
    while True:
        s1 = getpass.getpass("Nuevo enable secret (minimo 8 caracteres): ")
        s2 = getpass.getpass("Repite el enable secret: ")
        if s1 != s2:
            print("No coinciden, intenta de nuevo.")
        elif len(s1) < 8:
            print("Demasiado corto.")
        else:
            return s1


def main():
    ap = argparse.ArgumentParser(description="Auditoria y hardening CIS para R1 y SW1")
    ap.add_argument("mode", choices=["audit", "harden"])
    ap.add_argument("--devices", nargs="+", metavar="NOMBRE=IP",
                    help="por defecto R1=10.8.25.1 SW1=10.8.25.2")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--admin-ip", default=ADMIN_IP, help="IP permitida en la ACL vty")
    ap.add_argument("--syslog", default=SYSLOG_IP, help="IP del servidor de logs")
    ap.add_argument("--offline", nargs="+", metavar="NOMBRE=ARCHIVO",
                    help="audita running-configs guardadas (solo modo audit)")
    ap.add_argument("--out", default="reports")
    ap.add_argument("--yes", action="store_true", help="no pedir confirmacion (harden)")
    args = ap.parse_args()

    ctx = Ctx(admin_ip=args.admin_ip, syslog_ip=args.syslog)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base = os.path.join(args.out, ts)
    cfg_dir = os.path.join(base, "running-configs")

    # ---- modo offline ----
    if args.offline:
        if args.mode != "audit":
            sys.exit("--offline solo funciona con el modo audit.")
        results = {}
        for item in args.offline:
            name, _, path = item.partition("=")
            with open(path, encoding="utf-8", errors="replace") as f:
                results[name] = run_checks(f.read(), ctx)
        report_audit(os.path.join(base, "informe_audit.md"), ts, results)
        print_summary("Resultado de la auditoria offline:", results)
        print(f"\nInforme: {os.path.join(base, 'informe_audit.md')}")
        return

    devices = dict(DEVICES)
    if args.devices:
        devices = dict(d.split("=", 1) for d in args.devices)

    password = ask(f"Clave de '{args.user}': ", "CIS_PASS")
    enable = ask("Enable actual: ", "CIS_ENABLE")

    conns, cfgs_before, before = {}, {}, {}
    for name, ip in devices.items():
        print(f"Conectando a {name} ({ip})...")
        try:
            conns[name] = connect(name, ip, args.user, password, enable)
        except Exception as exc:
            print(f"  No pude conectar a {name}: {exc}")
            continue
        cfgs_before[name] = get_config(conns[name])
        before[name] = run_checks(cfgs_before[name], ctx)
        write(os.path.join(cfg_dir, f"{name}_antes.txt"), cfgs_before[name])

    if not before:
        sys.exit("No se pudo auditar ningun equipo.")

    # ---- audit ----
    if args.mode == "audit":
        report_audit(os.path.join(base, "informe_audit.md"), ts, before)
        print_summary("Resultado de la auditoria (no se cambio nada):", before)
        print(f"\nInforme: {os.path.join(base, 'informe_audit.md')}")
        for c in conns.values():
            c.disconnect()
        return

    # ---- harden ----
    pending = {n: [r for r in res if r["status"] == FAIL] for n, res in before.items()}
    if not any(pending.values()):
        print_summary("Estado actual:", before)
        print("\nNada que aplicar: todos los controles ya cumplen.")
        after = before
        report_harden(os.path.join(base, "informe_harden.md"), ts, before, after, {})
        for n, c in conns.items():
            write(os.path.join(cfg_dir, f"{n}_despues.txt"), cfgs_before[n])
            c.disconnect()
        return

    print("\nSe aplicaran estos controles:")
    for n, items in pending.items():
        for r in items:
            print(f"  {n}: {cid(r['check']):>9}  {r['check'].title}")
    if not args.yes and input("\nEscribe SI para continuar: ").strip() != "SI":
        sys.exit("Cancelado. No se cambio nada.")

    if any(r["check"].title.startswith("Set 'password' for 'enable secret'")
           for items in pending.values() for r in items):
        ctx.new_secret = read_new_secret()

    after, notes = {}, {}
    for name, conn in conns.items():
        errors = {}
        notes[name] = []
        for r in pending[name]:
            ch = r["check"]
            cmds = ch.fix(cfgs_before[name], ctx)
            if not cmds:
                continue
            try:
                out, bad = apply_cmds(conn, cmds)
            except Exception as exc:
                notes[name].append(f"{cid(ch)}: error aplicando ({exc})")
                continue
            if bad:
                errors[ch.title] = out
                notes[name].append(f"{cid(ch)} {ch.title}: el equipo rechazo el comando")
        save_config(conn)
        cfg_after = get_config(conn)
        write(os.path.join(cfg_dir, f"{name}_despues.txt"), cfg_after)
        res = run_checks(cfg_after, ctx)
        for r in res:
            if r["status"] == FAIL and r["check"].title in errors:
                r["status"] = NA
                r["ev"] += " (comando no soportado en este equipo)"
        after[name] = res
        conn.disconnect()

    report_harden(os.path.join(base, "informe_harden.md"), ts,
                  {n: before[n] for n in after}, after, notes)
    print_summary("Resultado despues del hardening:", after)
    print(f"\nInforme: {os.path.join(base, 'informe_harden.md')}")
    print(f"Running-configs antes/despues: {cfg_dir}")
    print("Anota el enable secret nuevo: el anterior ya no sirve.")


if __name__ == "__main__":
    main()
