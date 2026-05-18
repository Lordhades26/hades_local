#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         HADES-LOCAL v1.1 — Autonomous Security Agent            ║
║     Heuristic Automated Data & Execution System (Local)         ║
║  Compatible: Kali Linux | Parrot/Purple OS | Ubuntu | Debian    ║
╚══════════════════════════════════════════════════════════════════╝

USO:
    python3 hades_local.py start              → Shell interactivo
    python3 hades_local.py start --auto       → Modo autónomo
    python3 hades_local.py scan <TARGET>      → Escaneo rápido
    python3 hades_local.py fullaudit <RANGE>  → Auditoría completa automática
    python3 hades_local.py audit <TARGET>     → Auditoría ISO 27001
    python3 hades_local.py analyze <FILE>     → Análisis forense
    python3 hades_local.py stop               → Detener agente
    python3 hades_local.py status             → Estado del agente
    python3 hades_local.py tools              → Herramientas detectadas
"""

import os, sys, json, time, signal, shutil, subprocess, argparse, re
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
HADES_VERSION  = "1.2.0"
def _ollama_candidates():
    """URLs base candidatas para autodetectar Ollama en cualquier entorno:
    Linux nativo (Kali/Parrot/Purple/Ubuntu/Debian), WSL2, o VM NAT."""
    import os as _os, re as _re, subprocess as _sp
    cands = []
    env = _os.environ.get("HADES_OLLAMA_URL") or _os.environ.get("OLLAMA_HOST")
    if env:
        if not env.startswith("http"):
            env = "http://" + env
        if ":" not in env.split("//", 1)[1]:
            env += ":11434"
        cands.append(env.rstrip("/"))
    cands += ["http://127.0.0.1:11434", "http://localhost:11434"]
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    ip = line.split()[1].strip()
                    if ip and not ip.startswith("127."):
                        cands.append("http://%s:11434" % ip)
                    break
    except Exception:
        pass
    cands.append("http://host.docker.internal:11434")
    try:
        out = _sp.run(["ip", "route"], capture_output=True,
                       text=True, timeout=3).stdout
        m = _re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            cands.append("http://%s:11434" % m.group(1))
    except Exception:
        pass
    cands.append("http://10.0.2.2:11434")
    seen, uniq = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def resolve_ollama_base():
    import urllib.request
    for base in _ollama_candidates():
        try:
            with urllib.request.urlopen(base + "/api/tags", timeout=2) as r:
                if getattr(r, "status", 200) == 200:
                    return base
        except Exception:
            continue
    return "http://127.0.0.1:11434"


OLLAMA_BASE    = resolve_ollama_base()
OLLAMA_URL     = OLLAMA_BASE + "/api/generate"
HADES_MODEL    = "HADES-AUTO"
FALLBACK_MODEL = "qwen2.5:7b"
PID_FILE       = "/tmp/hades_local.pid"
LOG_FILE       = "/tmp/hades_local.log"
REPORT_DIR     = Path.home() / "hades_reports"
OLLAMA_TIMEOUT = 300  # 5 minutos — evita timeout en modelos lentos

class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    BLUE="\033[94m"; CYAN="\033[96m"; WHITE="\033[97m"
    BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.RED}{C.BOLD}
 ██╗  ██╗ █████╗ ██████╗ ███████╗███████╗
 ██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
 ███████║███████║██║  ██║█████╗  ███████╗
 ██╔══██║██╔══██║██║  ██║██╔══╝  ╚════██║
 ██║  ██║██║  ██║██████╔╝███████╗███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
{C.RESET}{C.CYAN}       LOCAL SECURITY AGENT v{HADES_VERSION}
{C.DIM}  Heuristic Automated Data & Execution System
{C.RESET}"""

# ─────────────────────────────────────────────
# DETECCIÓN DE HERRAMIENTAS Y OS
# ─────────────────────────────────────────────
TOOL_CATALOG = {
    "nmap":         {"category":"recon",   "desc":"Escáner de red y puertos"},
    "masscan":      {"category":"recon",   "desc":"Escáner masivo de puertos"},
    "netdiscover":  {"category":"recon",   "desc":"Descubrimiento ARP"},
    "whois":        {"category":"recon",   "desc":"Consultas WHOIS"},
    "dig":          {"category":"recon",   "desc":"Consultas DNS"},
    "nikto":        {"category":"web",     "desc":"Escáner vulnerabilidades web"},
    "dirb":         {"category":"web",     "desc":"Fuerza bruta directorios"},
    "gobuster":     {"category":"web",     "desc":"Fuerza bruta DNS/web"},
    "sqlmap":       {"category":"web",     "desc":"Inyección SQL"},
    "whatweb":      {"category":"web",     "desc":"Identificación tecnologías web"},
    "wfuzz":        {"category":"web",     "desc":"Fuzzing web"},
    "msfconsole":   {"category":"exploit", "desc":"Metasploit Framework"},
    "searchsploit": {"category":"exploit", "desc":"Base de datos exploits"},
    "tshark":       {"category":"traffic", "desc":"Análisis de tráfico"},
    "tcpdump":      {"category":"traffic", "desc":"Captura de paquetes"},
    "wireshark":    {"category":"traffic", "desc":"Análisis visual paquetes"},
    "netstat":      {"category":"traffic", "desc":"Conexiones activas"},
    "ss":           {"category":"traffic", "desc":"Estadísticas sockets"},
    "aircrack-ng":  {"category":"wifi",    "desc":"Suite auditoría WiFi"},
    "airodump-ng":  {"category":"wifi",    "desc":"Captura handshakes WiFi"},
    "aireplay-ng":  {"category":"wifi",    "desc":"Inyección paquetes WiFi"},
    "iwconfig":     {"category":"wifi",    "desc":"Config interfaces inalámbricas"},
    "john":         {"category":"crack",   "desc":"John the Ripper"},
    "hashcat":      {"category":"crack",   "desc":"Cracking de hashes"},
    "hydra":        {"category":"crack",   "desc":"Fuerza bruta servicios"},
    "hashid":       {"category":"crack",   "desc":"Identificación de hashes"},
    "volatility3":  {"category":"forensic","desc":"Forense de memoria"},
    "binwalk":      {"category":"forensic","desc":"Análisis de firmware"},
    "strings":      {"category":"forensic","desc":"Extracción de strings"},
    "file":         {"category":"forensic","desc":"Identificación de archivos"},
    "exiftool":     {"category":"forensic","desc":"Metadatos de archivos"},
    "gdb":          {"category":"reverse", "desc":"Debugger GNU"},
    "radare2":      {"category":"reverse", "desc":"Framework reversing"},
    "objdump":      {"category":"reverse", "desc":"Desensamblado binarios"},
    "curl":         {"category":"misc",    "desc":"Cliente HTTP"},
    "wget":         {"category":"misc",    "desc":"Descargador HTTP"},
    "python3":      {"category":"misc",    "desc":"Python 3"},
    "git":          {"category":"misc",    "desc":"Control de versiones"},
    "openssl":      {"category":"misc",    "desc":"Toolkit SSL/TLS"},
    "gpg":          {"category":"misc",    "desc":"Cifrado PGP"},
}

def detect_tools():
    return {t: m for t, m in TOOL_CATALOG.items() if shutil.which(t)}

def detect_os():
    try:
        c = open("/etc/os-release").read().lower()
        for k in ["kali","parrot","purple","ubuntu","debian","arch"]:
            if k in c: return k
    except: pass
    return "linux"

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"INFO":C.CYAN,"OK":C.GREEN,"WARN":C.YELLOW,"ERROR":C.RED,"HADES":C.RED+C.BOLD}
    color = colors.get(level, C.WHITE)
    line = f"{C.DIM}[{ts}]{C.RESET} {color}[{level}]{C.RESET} {msg}"
    print(line)
    try:
        with open(LOG_FILE,"a") as f:
            f.write(f"[{datetime.now().isoformat()}][{level}] {msg}\n")
    except: pass

def log_ok(m):   log(m,"OK")
def log_warn(m): log(m,"WARN")
def log_err(m):  log(m,"ERROR")
def log_h(m):    log(m,"HADES")

# ─────────────────────────────────────────────
# OLLAMA ENGINE — con retry y timeout extendido
# ─────────────────────────────────────────────
def check_ollama():
    import urllib.request
    try:
        with urllib.request.urlopen(
            OLLAMA_BASE + "/api/tags", timeout=10
        ) as r:
            data = json.loads(r.read())
            full = [m["name"] for m in data.get("models", [])]   # ["llama3:latest","qwen2.5:3b"]
            if not full:
                return None
            # base -> nombre completo (con etiqueta) para que Ollama lo acepte tal cual
            bases = {}
            for n in full:
                bases.setdefault(n.split(":")[0], n)
            for pref in [HADES_MODEL, FALLBACK_MODEL]:
                b = pref.split(":")[0]
                if b in bases:
                    return bases[b]
            return full[0]
    except: pass
    return None

def ask_hades(prompt, model=None, timeout=None):
    import urllib.request, urllib.error
    if timeout is None: timeout = OLLAMA_TIMEOUT
    if model is None:   model = HADES_MODEL

    # Limitar prompt para evitar timeouts
    prompt = prompt[:6000]

    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature":0.3,"top_p":0.9,"num_predict":800}
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type":"application/json"}, method="POST"
    )

    for attempt in range(2):  # 2 intentos
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read()).get("response","").strip()
        except urllib.error.URLError as e:
            if attempt == 0:
                log_warn(f"Ollama: reintentando... ({e})")
                time.sleep(3)
            else:
                log_err(f"Ollama no responde: {e}")
        except Exception as e:
            log_err(f"Error Ollama: {e}")
            break
    return None

# ─────────────────────────────────────────────
# EJECUCIÓN DE COMANDOS
# ─────────────────────────────────────────────
def run_cmd(cmd, timeout=180):
    log(f"Ejecutando: {C.YELLOW}{cmd}{C.RESET}")
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"[TIMEOUT {timeout}s]", -1
    except Exception as e:
        return "", str(e), -1

def run_tool(tool, args, timeout=180):
    if not shutil.which(tool):
        return None, f"'{tool}' no instalado.", 1
    return run_cmd(f"{tool} {args}", timeout)

# ─────────────────────────────────────────────
# PARSER DE NMAP — extrae hosts y servicios
# ─────────────────────────────────────────────
def parse_nmap_hosts(nmap_output):
    """
    Parsea output de nmap y retorna lista de:
    {"ip": "x.x.x.x", "ports": [{"port":"80","service":"http","version":"..."}]}
    """
    hosts = []
    current = None

    for line in nmap_output.splitlines():
        # Nuevo host
        m = re.match(r"Nmap scan report for (?:[\w.-]+ \()?(\d+\.\d+\.\d+\.\d+)\)?", line)
        if m:
            if current: hosts.append(current)
            current = {"ip": m.group(1), "ports": [], "raw": ""}
            continue

        if current is None: continue
        current["raw"] += line + "\n"

        # Puerto abierto
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
        if m:
            current["ports"].append({
                "port": m.group(1),
                "service": m.group(2),
                "version": m.group(3).strip()
            })

    if current: hosts.append(current)
    return hosts

# ─────────────────────────────────────────────
# MÓDULO DE AUDITORÍA AUTOMÁTICA COMPLETA
# ─────────────────────────────────────────────
class HadesEngine:
    def __init__(self):
        self.tools = detect_tools()
        self.os_profile = detect_os()
        self.model = check_ollama()
        self.findings = []
        REPORT_DIR.mkdir(exist_ok=True)

    def _has(self, t): return t in self.tools

    def _ask(self, prompt, timeout=None):
        if not self.model:
            log_err("Ollama no disponible.")
            return None
        return ask_hades(prompt, self.model, timeout)

    def _save_report(self, name, content):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORT_DIR / f"hades_{name}_{ts}.md"
        path.write_text(content, encoding="utf-8")
        log_ok(f"Reporte guardado: {path}")
        return path

    def _tools_summary(self):
        cats = {}
        for t, m in self.tools.items():
            cats.setdefault(m["category"],[]).append(t)
        return "\n".join(f"  [{c.upper()}]: {', '.join(ts)}" for c,ts in cats.items())

    # ── ESCANEO RÁPIDO ─────────────────────────
    def quick_scan(self, target):
        log_h(f"ESCANEO RÁPIDO: {target}")
        if not self._has("nmap"):
            log_warn("nmap no disponible.")
            return
        stdout, _, _ = run_tool("nmap", f"-sV -T4 --top-ports 1000 {target}", timeout=120)
        print(f"\n{C.YELLOW}[NMAP QUICK]{C.RESET}\n{stdout[:2000]}")
        analysis = self._ask(
            f"Analiza este escaneo nmap de {target}. Máximo 6 líneas. "
            f"Identifica puertos críticos y riesgo:\n{stdout[:2000]}"
        )
        if analysis:
            print(f"\n{C.CYAN}{analysis}{C.RESET}\n")

    # ── RECONOCIMIENTO ─────────────────────────
    def recon(self, target):
        log_h(f"RECONOCIMIENTO: {target}")
        findings = {}

        if self._has("nmap"):
            stdout, _, _ = run_tool("nmap", f"-sV -sC -T4 --open {target}", timeout=240)
            findings["nmap"] = stdout
            print(f"\n{C.YELLOW}[NMAP OUTPUT]{C.RESET}\n{stdout[:3000]}")
        else:
            stdout, _, _ = run_cmd("ss -tulnp")
            findings["ss"] = stdout

        if self._has("whois") and not any(target.startswith(p) for p in ["192.","10.","172."]):
            stdout, _, _ = run_tool("whois", target, 30)
            findings["whois"] = stdout[:500]

        raw = json.dumps(findings, ensure_ascii=False)[:3000]
        analysis = self._ask(
            f"Eres HADES, analista de seguridad. Analiza reconocimiento de {target}:\n{raw}\n\n"
            f"Responde con: 1)Superficie de ataque 2)Servicios críticos 3)Vulnerabilidades potenciales "
            f"4)Próximos pasos 5)Nivel de riesgo: BAJO/MEDIO/ALTO/CRÍTICO"
        )
        if analysis:
            log_h("ANÁLISIS IA:")
            print(f"\n{C.CYAN}{analysis}{C.RESET}\n")
            self.findings.append({"phase":"recon","target":target,"analysis":analysis})

        return findings, analysis

    # ── AUDITORÍA COMPLETA AUTOMÁTICA ──────────
    def full_audit(self, network_range):
        """
        Flujo completo automático:
        1. Descubrir hosts activos
        2. Por cada host: escaneo de puertos + servicios
        3. Análisis de vulnerabilidades por servicio
        4. Nikto en servicios web
        5. Análisis SSL en HTTPS
        6. Análisis IA de cada host
        7. Reporte Markdown completo
        """
        log_h(f"AUDITORÍA COMPLETA iniciada: {network_range}")
        log_warn("Este proceso puede tomar varios minutos...")

        report = []
        report.append(f"# HADES — Informe de Seguridad\n")
        report.append(f"**Red auditada:** `{network_range}`  ")
        report.append(f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        report.append(f"**Agente:** HADES-LOCAL v{HADES_VERSION}  ")
        report.append(f"**Modelo IA:** {self.model or 'No disponible'}\n")
        report.append("---\n")

        # ── FASE 1: Descubrimiento de hosts ───
        log_h("FASE 1 — Descubrimiento de hosts activos")
        report.append("## Fase 1 — Descubrimiento de Hosts\n")

        if self._has("nmap"):
            stdout, _, _ = run_tool("nmap", f"-sn {network_range}", timeout=60)
            active_ips = re.findall(r"Nmap scan report for (?:[\w.-]+ \()?(\d+\.\d+\.\d+\.\d+)\)?", stdout)
            report.append(f"**Hosts activos encontrados:** {len(active_ips)}\n")
            for ip in active_ips:
                report.append(f"- `{ip}`")
            report.append("")
            print(f"\n{C.GREEN}Hosts activos: {active_ips}{C.RESET}\n")
        else:
            log_err("nmap requerido para auditoría completa.")
            return

        if not active_ips:
            log_warn("No se encontraron hosts activos.")
            return

        # ── FASE 2: Auditoría por host ─────────
        host_summaries = []

        for ip in active_ips:
            log_h(f"FASE 2 — Auditando host: {ip}")
            report.append(f"\n---\n## Host: `{ip}`\n")
            host_data = {"ip": ip, "ports": [], "vulns": [], "risk": "DESCONOCIDO"}

            # Escaneo completo de puertos y servicios
            log(f"Escaneando puertos y servicios en {ip}...")
            stdout, _, _ = run_tool("nmap", f"-sV -sC -T4 --open -p- {ip}", timeout=300)
            hosts_parsed = parse_nmap_hosts(stdout)
            host_info = next((h for h in hosts_parsed if h["ip"] == ip), None)

            if host_info and host_info["ports"]:
                host_data["ports"] = host_info["ports"]
                report.append(f"### Puertos y Servicios\n")
                report.append("| Puerto | Servicio | Versión |")
                report.append("|--------|----------|---------|")
                for p in host_info["ports"]:
                    report.append(f"| {p['port']}/tcp | {p['service']} | {p['version']} |")
                report.append("")

            # Escaneo de vulnerabilidades con nmap scripts
            log(f"Escaneando vulnerabilidades en {ip}...")
            vuln_out, _, _ = run_tool(
                "nmap", f"--script vuln -T4 --open {ip}", timeout=300
            )
            vuln_matches = re.findall(r"(CVE-\d{4}-\d+|VULNERABLE|LIKELY VULNERABLE)", vuln_out, re.IGNORECASE)
            if vuln_matches:
                host_data["vulns"] = list(set(vuln_matches))
                report.append(f"### Vulnerabilidades Detectadas (nmap --script vuln)\n")
                report.append(f"```\n{vuln_out[:2000]}\n```\n")
            else:
                report.append(f"### Vulnerabilidades\nNo se detectaron CVEs conocidos con nmap.\n")

            # Nikto en servicios HTTP
            http_ports = [p for p in host_data["ports"] if p["service"] in ["http","http-alt","ssl/http"]]
            for hp in http_ports[:2]:  # máximo 2 puertos web por host
                proto = "https" if "ssl" in hp["service"] else "http"
                url = f"{proto}://{ip}:{hp['port']}"
                log(f"Nikto en {url}...")
                if self._has("nikto"):
                    nikto_out, _, _ = run_tool("nikto", f"-h {url} -maxtime 60", timeout=90)
                    report.append(f"### Nikto — {url}\n```\n{nikto_out[:1500]}\n```\n")

            # SSL check
            ssl_ports = [p for p in host_data["ports"] if "ssl" in p["service"] or p["port"] in ["443","8443","8000"]]
            for sp in ssl_ports[:1]:
                log(f"Verificando SSL en {ip}:{sp['port']}...")
                ssl_out, _, _ = run_cmd(
                    f"echo | openssl s_client -connect {ip}:{sp['port']} -brief 2>&1 | head -20"
                )
                report.append(f"### SSL/TLS — Puerto {sp['port']}\n```\n{ssl_out[:500]}\n```\n")

            # Análisis IA del host
            log(f"Analizando {ip} con HADES-IA...")
            host_context = (
                f"IP: {ip}\n"
                f"Puertos: {json.dumps(host_data['ports'])}\n"
                f"CVEs encontrados: {host_data['vulns']}\n"
                f"Extracto nmap vuln:\n{vuln_out[:1000]}"
            )
            ai_analysis = self._ask(
                f"Eres HADES, experto en ciberseguridad ISO 27001. Analiza este host:\n\n"
                f"{host_context}\n\n"
                f"Proporciona:\n"
                f"1. Nivel de riesgo: BAJO/MEDIO/ALTO/CRÍTICO\n"
                f"2. Vulnerabilidades críticas identificadas\n"
                f"3. Vectores de ataque probables\n"
                f"4. Recomendaciones de remediación concretas\n"
                f"5. Controles ISO 27001 aplicables (Anexo A)\n"
                f"Sé técnico y conciso. Máximo 300 palabras.",
                timeout=300
            )

            if ai_analysis:
                host_data["ai_analysis"] = ai_analysis
                report.append(f"### Análisis HADES-IA\n{ai_analysis}\n")
                # Extraer nivel de riesgo
                for nivel in ["CRÍTICO","ALTO","MEDIO","BAJO"]:
                    if nivel in ai_analysis.upper():
                        host_data["risk"] = nivel
                        break

            host_summaries.append(host_data)
            log_ok(f"Host {ip} auditado. Riesgo: {host_data['risk']}")

        # ── FASE 3: Resumen ejecutivo ──────────
        log_h("FASE 3 — Generando resumen ejecutivo...")
        report.append("\n---\n## Resumen Ejecutivo\n")

        summary_data = json.dumps([
            {"ip": h["ip"], "ports": len(h["ports"]), "vulns": h["vulns"], "risk": h["risk"]}
            for h in host_summaries
        ], ensure_ascii=False)

        exec_summary = self._ask(
            f"Eres HADES. Genera un resumen ejecutivo para un CISO sobre esta auditoría de red {network_range}:\n\n"
            f"{summary_data}\n\n"
            f"Incluye: 1)Hallazgos críticos prioritarios 2)Superficie de ataque total "
            f"3)Recomendaciones top 5 ordenadas por urgencia 4)Cumplimiento ISO 27001. "
            f"Tono ejecutivo y técnico. Máximo 400 palabras.",
            timeout=300
        )

        if exec_summary:
            report.append(exec_summary)
            print(f"\n{C.BOLD}{'='*60}{C.RESET}")
            print(f"{C.RED}{C.BOLD}RESUMEN EJECUTIVO HADES{C.RESET}")
            print(f"{C.BOLD}{'='*60}{C.RESET}")
            print(f"{C.CYAN}{exec_summary}{C.RESET}\n")

        # Tabla resumen de hosts
        report.append("\n### Tabla de Riesgos\n")
        report.append("| IP | Puertos Abiertos | CVEs | Riesgo |")
        report.append("|----|-----------------|------|--------|")
        risk_colors = {"CRÍTICO":"🔴","ALTO":"🟠","MEDIO":"🟡","BAJO":"🟢","DESCONOCIDO":"⚪"}
        for h in host_summaries:
            icon = risk_colors.get(h["risk"],"⚪")
            cves = ", ".join(h["vulns"][:3]) if h["vulns"] else "Ninguno"
            report.append(f"| `{h['ip']}` | {len(h['ports'])} | {cves} | {icon} {h['risk']} |")

        # Guardar reporte
        full_report = "\n".join(report)
        path = self._save_report("full_audit", full_report)

        print(f"\n{C.GREEN}{C.BOLD}✅ AUDITORÍA COMPLETA{C.RESET}")
        print(f"   Hosts auditados : {len(host_summaries)}")
        print(f"   Reporte guardado: {path}\n")

        return path

    # ── AUDITORÍA ISO 27001 ────────────────────
    def audit_iso27001(self, target):
        log_h(f"AUDITORÍA ISO 27001 — {target}")
        report = [f"# Auditoría ISO 27001\n**Objetivo:** {target}\n**Fecha:** {datetime.now().isoformat()}\n"]

        for title, fn in [
            ("A.12.6 Gestión de Vulnerabilidades", lambda: self._audit_vulns(target)),
            ("A.13.1 Seguridad de Red",             lambda: self._audit_network(target)),
            ("A.9.4 Control de Acceso",             lambda: self._audit_access(target)),
        ]:
            log(f"Fase: {title}")
            result = fn()
            report.append(f"## {title}\n{result}\n")
            time.sleep(1)

        full = "\n".join(report)
        path = self._save_report("iso27001", full)

        summary = self._ask(
            f"Resumen ejecutivo CISO para auditoría ISO 27001 de {target}. "
            f"3 párrafos. Hallazgos y recomendaciones:\n{full[:2000]}"
        )
        if summary:
            print(f"\n{C.BOLD}RESUMEN:{C.RESET}\n{C.CYAN}{summary}{C.RESET}\n")
        return path

    def _audit_vulns(self, t):
        if self._has("nmap"):
            out, _, _ = run_tool("nmap", f"--script vuln -T4 {t}", 300)
            return f"```\n{out[:2000]}\n```"
        return "nmap no disponible."

    def _audit_network(self, t):
        r = []
        if self._has("nmap"):
            out, _, _ = run_tool("nmap", f"-sn {t}/24", 60)
            r.append(f"**Hosts activos:**\n```\n{out[:500]}\n```")
        out, _, _ = run_cmd("ss -tulnp")
        r.append(f"**Servicios locales:**\n```\n{out[:500]}\n```")
        return "\n".join(r)

    def _audit_access(self, t):
        r = []
        out, _, _ = run_cmd("cat /etc/passwd | grep -v nologin | grep -v false")
        r.append(f"**Usuarios con shell:**\n```\n{out[:500]}\n```")
        out, _, _ = run_cmd("sudo -l 2>/dev/null | head -20")
        r.append(f"**Privilegios sudo:**\n```\n{out[:300]}\n```")
        return "\n".join(r)

    # ── ANÁLISIS DE ARCHIVO ────────────────────
    def analyze_file(self, filepath):
        if not os.path.exists(filepath):
            log_err(f"Archivo no encontrado: {filepath}")
            return
        ext = Path(filepath).suffix.lower()
        log_h(f"ANALIZANDO: {filepath}")
        findings = {}

        if self._has("file"):
            out, _, _ = run_tool("file", filepath)
            findings["file_type"] = out

        if ext in [".pcap",".pcapng",".cap"] and self._has("tshark"):
            out, _, _ = run_tool("tshark", f"-r {filepath} -q -z io,phs", 60)
            findings["traffic"] = out[:1000]

        if ext in [".txt",".hash"] and self._has("hashid"):
            first = open(filepath).readline().strip()
            out, _, _ = run_tool("hashid", f'"{first}"')
            findings["hash_type"] = out

        if self._has("strings"):
            out, _, _ = run_tool("strings", f"{filepath} | head -50")
            findings["strings"] = out

        raw = json.dumps(findings, ensure_ascii=False)[:2000]
        analysis = self._ask(
            f"Analiza forense del archivo {filepath}:\n{raw}\n\n"
            f"Identifica: tipo, datos de seguridad relevantes, IOCs, acciones recomendadas."
        )
        if analysis:
            log_h("ANÁLISIS FORENSE:")
            print(f"\n{C.CYAN}{analysis}{C.RESET}\n")
        return self._save_report("file", f"# Análisis: {filepath}\n{raw}\n\n## IA\n{analysis or 'N/A'}")

    # ── SHELL INTERACTIVO ──────────────────────
    def interactive_shell(self):
        print(BANNER)
        log_ok(f"OS: {self.os_profile.upper()} | Modelo: {self.model or 'NO DISPONIBLE'} | Herramientas: {len(self.tools)}")
        log(f"Escribe 'help' para ver comandos.\n")

        cmds = {
            "scan <ip>":         "Escaneo rápido de puertos",
            "recon <ip/red>":    "Reconocimiento completo",
            "fullaudit <red>":   "Auditoría automática completa con reporte",
            "audit <ip>":        "Auditoría ISO 27001",
            "analyze <archivo>": "Análisis forense de archivo",
            "ask <pregunta>":    "Consulta libre a HADES-IA",
            "tools":             "Listar herramientas",
            "findings":          "Ver hallazgos de la sesión",
            "clear":             "Limpiar pantalla",
            "exit":              "Salir",
        }

        while True:
            try:
                raw = input(f"\n{C.RED}{C.BOLD}HADES{C.RESET}{C.DIM}@{self.os_profile}{C.RESET} {C.CYAN}▶{C.RESET} ").strip()
                if not raw: continue
                parts = raw.split(None, 1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd in ["exit","quit","q"]:
                    log("Sesión terminada.")
                    break
                elif cmd == "help":
                    print(f"\n{C.BOLD}Comandos:{C.RESET}")
                    for c, d in cmds.items():
                        print(f"  {C.CYAN}{c:<28}{C.RESET} {d}")
                elif cmd == "tools":
                    print(f"\n{C.BOLD}Herramientas detectadas ({len(self.tools)}):{C.RESET}")
                    print(self._tools_summary())
                elif cmd == "findings":
                    if not self.findings:
                        print("Sin hallazgos en esta sesión.")
                    else:
                        for i, f in enumerate(self.findings, 1):
                            print(f"\n{C.YELLOW}[{i}] {f['phase'].upper()} — {f.get('target','')}{C.RESET}")
                            print(f.get("analysis",""))
                elif cmd == "clear":
                    os.system("clear"); print(BANNER)
                elif cmd == "scan":
                    self.quick_scan(arg) if arg else log_warn("Uso: scan <target>")
                elif cmd == "recon":
                    self.recon(arg) if arg else log_warn("Uso: recon <target>")
                elif cmd == "fullaudit":
                    self.full_audit(arg) if arg else log_warn("Uso: fullaudit <red/CIDR>")
                elif cmd == "audit":
                    self.audit_iso27001(arg) if arg else log_warn("Uso: audit <target>")
                elif cmd == "analyze":
                    self.analyze_file(arg) if arg else log_warn("Uso: analyze <filepath>")
                elif cmd == "ask":
                    if not arg:
                        log_warn("Uso: ask <pregunta>")
                    else:
                        resp = self._ask(
                            f"Contexto: OS={self.os_profile}, herramientas={list(self.tools.keys())}\n"
                            f"Pregunta del operador: {arg}"
                        )
                        if resp: print(f"\n{C.CYAN}{resp}{C.RESET}")
                else:
                    log_warn(f"Comando desconocido: '{cmd}'. Escribe 'help'.")

            except KeyboardInterrupt:
                print(f"\n{C.DIM}[Ctrl+C — escribe 'exit' para salir]{C.RESET}")
            except EOFError:
                break

    # ── MODO AUTÓNOMO ──────────────────────────
    def auto_mode(self):
        print(BANNER)
        log_h("MODO AUTÓNOMO — Ciclo cada 30 minutos")
        cycle = 0
        while True:
            cycle += 1
            log_h(f"CICLO #{cycle} — {datetime.now().strftime('%H:%M:%S')}")
            out, _, _ = run_cmd("ip route | grep -v default | awk '{print $1}' | head -3")
            nets = [n.strip() for n in out.splitlines() if "/" in n]
            if nets:
                for net in nets[:2]:
                    self.full_audit(net)
            else:
                log_warn("Sin redes detectadas. Ejecutando diagnóstico local...")
                out, _, _ = run_cmd("ss -tulnp")
                resp = self._ask(f"Analiza servicios activos y postura de seguridad:\n{out[:2000]}")
                if resp: print(f"\n{C.CYAN}{resp}{C.RESET}\n")
            log(f"Próximo ciclo en 30 minutos...")
            time.sleep(1800)

# ─────────────────────────────────────────────
# PID / STATUS
# ─────────────────────────────────────────────
def write_pid():
    open(PID_FILE,"w").write(str(os.getpid()))

def read_pid():
    try: return int(open(PID_FILE).read())
    except: return None

def stop_agent():
    pid = read_pid()
    if not pid:
        print(f"{C.YELLOW}No hay agente en background.{C.RESET}"); return
    try:
        os.kill(pid, signal.SIGTERM)
        os.remove(PID_FILE)
        print(f"{C.GREEN}Agente detenido (PID {pid}).{C.RESET}")
    except:
        print(f"{C.YELLOW}Proceso {pid} ya no existe.{C.RESET}")
        try: os.remove(PID_FILE)
        except: pass

def agent_status():
    pid = read_pid()
    tools = detect_tools()
    model = check_ollama()
    print(f"\n{C.BOLD}══════════════ HADES STATUS ══════════════{C.RESET}")
    print(f"  Sistema OS    : {C.CYAN}{detect_os().upper()}{C.RESET}")
    print(f"  Ollama modelo : {C.GREEN if model else C.RED}{model or 'NO DISPONIBLE'}{C.RESET}")
    print(f"  Herramientas  : {C.GREEN}{len(tools)}{C.RESET} detectadas")
    print(f"  PID agente    : {C.GREEN if pid else C.DIM}{pid or 'No activo'}{C.RESET}")
    print(f"  Ollama URL    : {OLLAMA_URL}")
    print(f"  Log           : {LOG_FILE}")
    print(f"  Reportes      : {REPORT_DIR}")
    print(f"{C.BOLD}══════════════════════════════════════════{C.RESET}\n")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="HADES-LOCAL v1.1", formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("start");      p.add_argument("--auto", action="store_true")
    p = sub.add_parser("scan");       p.add_argument("target")
    p = sub.add_parser("recon");      p.add_argument("target")
    p = sub.add_parser("fullaudit");  p.add_argument("range")
    p = sub.add_parser("audit");      p.add_argument("target")
    p = sub.add_parser("analyze");    p.add_argument("file")
    sub.add_parser("stop")
    sub.add_parser("status")
    sub.add_parser("tools")

    args = parser.parse_args()
    if not args.command:
        print(BANNER); parser.print_help(); sys.exit(0)

    engine = HadesEngine()

    if   args.command == "start":     engine.auto_mode() if args.auto else engine.interactive_shell()
    elif args.command == "scan":      print(BANNER); engine.quick_scan(args.target)
    elif args.command == "recon":     print(BANNER); engine.recon(args.target)
    elif args.command == "fullaudit": print(BANNER); engine.full_audit(args.range)
    elif args.command == "audit":     print(BANNER); engine.audit_iso27001(args.target)
    elif args.command == "analyze":   print(BANNER); engine.analyze_file(args.file)
    elif args.command == "stop":      stop_agent()
    elif args.command == "status":    agent_status()
    elif args.command == "tools":
        tools = detect_tools()
        print(f"\n{C.BOLD}Herramientas detectadas en {detect_os().upper()} ({len(tools)} total):{C.RESET}")
        cats = {}
        for t, m in tools.items():
            cats.setdefault(m["category"],[]).append((t, m["desc"]))
        for cat, items in sorted(cats.items()):
            print(f"\n  {C.CYAN}[{cat.upper()}]{C.RESET}")
            for tool, desc in items:
                print(f"    {C.GREEN}✓{C.RESET} {tool:<20} {C.DIM}{desc}{C.RESET}")
        print()

if __name__ == "__main__":
    main()
