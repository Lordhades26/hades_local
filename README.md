# HADES-LOCAL — Agente Autónomo de Ciberseguridad

<div align="center">

```
 ██╗  ██╗ █████╗ ██████╗ ███████╗███████╗
 ██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
 ███████║███████║██║  ██║█████╗  ███████╗
 ██╔══██║██╔══██║██║  ██║██╔══╝  ╚════██║
 ██║  ██║██║  ██║██████╔╝███████╗███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
```

**Heuristic Automated Data & Execution System**

![Version](https://img.shields.io/badge/version-2.1.0--REDTEAM-red)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Parrot%20%7C%20Purple-lightgrey)
![AI](https://img.shields.io/badge/AI-Ollama%20Local-orange)
![Tier](https://img.shields.io/badge/edition-FREE-yellow)

*Agente Red Team autónomo impulsado por IA local. Sin cloud. Sin API keys.*

</div>

---

## ¿Qué es HADES-LOCAL?

HADES-LOCAL es un agente Red Team autónomo que combina herramientas ofensivas de ciberseguridad con inteligencia artificial local (Ollama). Ejecuta kill chains completos, explota vulnerabilidades, realiza movimiento lateral, captura credenciales y genera reportes ejecutivos — todo sin conexión a internet.

**No requiere internet para operar.** La IA corre 100% en tu máquina.

---

## Ediciones HADES

| Edición | Precio | OS soportados | Capacidades |
|---------|--------|---------------|-------------|
| **HADES FREE** (este repo) | Gratis | Kali Linux, Parrot OS, Purple Linux | Red Team completo en SO compatible; funciones básicas en cualquier Linux |
| **HADES CORE** | De pago | Cualquier Linux | Red Team completo sin restricción de SO |
| **HADES PRO** | De pago | Cualquier SO | Red Team completo + módulos enterprise + soporte |

> **En esta edición FREE:** Las capacidades Red Team (killchain, exploit, post-explotación, WiFi, pivoting, etc.) se activan **únicamente** en **Kali Linux**, **Parrot OS** y **Purple Linux**. En cualquier otro sistema operativo sólo estarán disponibles las funciones de auditoría básica (scan, recon, fullaudit, audit, analyze).

---

### Capacidades Red Team (Kali / Parrot / Purple)

- **Kill chain automatizado** — Reconocimiento → Enumeración → Escaneo de vulnerabilidades → Explotación → Post-explotación → Lateral movement en un solo comando
- **Explotación con Metasploit** — Sugerencia de módulo por IA + ejecución automatizada
- **Post-explotación local** — SUID, sudo -l, crontabs, variables de entorno, llaves SSH, escape Docker
- **Movimiento lateral** — secretsdump, psexec, wmiexec, pass-the-hash (impacket)
- **Captura de credenciales** — Responder LLMNR/NBT-NS
- **Ataques WiFi completos** — aircrack-ng: monitor → handshake → cracking
- **Ataques web** — sqlmap, nuclei, ffuf, nikto integrados
- **OSINT** — theHarvester, whois, registros DNS
- **Persistencia MITRE ATT&CK** — T1053 (cron), T1543 (servicio), T1546 (bashrc)

### Capacidades básicas (cualquier Linux)

- **Auditoría automática completa** — Descubre hosts, escanea puertos, detecta CVEs, genera reporte Markdown
- **Análisis IA por host** — Cada dispositivo analizado por el modelo de lenguaje local
- **Reportes profesionales** — Guardados automáticamente en `~/hades_reports/`
- **Shell interactivo** — Prompt dedicado con colores y autocompletado
- **Modo autónomo** — Escanea la red cada 30 minutos sin intervención humana

---

## Requisitos

### Obligatorios
- Python 3.8 o superior
- [Ollama](https://ollama.com) instalado (local o en red)
- Al menos un modelo descargado en Ollama

### Para capacidades básicas (cualquier Linux)
- `nmap` — Reconocimiento y detección de vulnerabilidades *(altamente recomendado)*
- `nikto` — Auditoría de servicios web
- `tshark` — Análisis de tráfico de red
- `john` / `hashcat` — Cracking de hashes

### Para capacidades Red Team completas (Kali / Parrot / Purple)
- `metasploit-framework` — Explotación automatizada
- `aircrack-ng` — Auditoría de redes WiFi
- `hydra` — Ataques de fuerza bruta
- `responder` — Captura de credenciales LLMNR/NBT-NS
- `sqlmap` — Inyección SQL automatizada
- `nuclei` — Escáner de vulnerabilidades masivo
- `ffuf` — Fuzzing web
- `enum4linux-ng` — Enumeración SMB/Samba
- `netexec` (ex-crackmapexec) — Auditoría de red Windows/AD
- `impacket` — Lateral movement (secretsdump, psexec, wmiexec)
- `theHarvester` — OSINT y recolección de información

---

## Instalación paso a paso

### Paso 1 — Verificar Python

```bash
python3 --version
# Debe ser 3.8 o superior
```

### Paso 2 — Clonar el repositorio

```bash
git clone https://github.com/Lordhades26/hades_local.git
cd hades_local
```

### Paso 3 — Instalar herramientas de seguridad

El script `install_tools.sh` instala todas las herramientas via `apt` (compatible con Kali, Parrot, Ubuntu y Debian):

```bash
sudo bash install_tools.sh
```

El script verifica cada herramienta al final e indica cuáles quedaron instaladas.

> **Nota:** Si estás en Kali Linux o Parrot OS, la mayoría de herramientas ya vienen preinstaladas. El script actualiza las faltantes.

### Paso 4 — Instalar Ollama

**En Linux nativo (Kali, Parrot, Ubuntu, Debian):**

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Verificar que Ollama esté corriendo:

```bash
ollama list
# Si no responde, iniciar el servicio:
sudo systemctl start ollama
# o manualmente:
ollama serve &
```

**En Windows (para usar con WSL):** Descargar el instalador desde [ollama.com/download/windows](https://ollama.com/download/windows) y ejecutarlo. Luego ver la sección [Configuración WSL](#configuración-en-windows--wsl) más abajo.

### Paso 5 — Descargar un modelo de IA

```bash
# Modelo recomendado (mejor rendimiento en seguridad):
ollama pull HADES-AUTO

# Si tu equipo tiene menos de 8 GB de RAM, usa este:
ollama pull qwen2.5:3b

# Verificar que el modelo está disponible:
ollama list
```

### Paso 6 — (Automático) Detección de Ollama

> **Desde la v2.1.0 no necesitas editar ningún archivo.** HADES **autodetecta**
> dónde está Ollama y qué modelo usar.

Al iniciar, `hades_local.py` prueba en orden y usa la primera URL que responda:

1. Variable de entorno `HADES_OLLAMA_URL` (o `OLLAMA_HOST`) — override manual
2. `http://127.0.0.1:11434` y `http://localhost:11434` — **Ollama en el propio Linux** (Kali/Parrot/Purple/Ubuntu/Debian nativo o VM)
3. El `nameserver` de `/etc/resolv.conf` — **WSL2** (Ollama en el host Windows)
4. `http://host.docker.internal:11434` — WSL2 moderno / Docker
5. El gateway por defecto (`ip route`) — **VM en VirtualBox/VMware con NAT**
6. `http://10.0.2.2:11434` — gateway NAT clásico de VirtualBox

El modelo también se detecta solo: usa cualquier modelo presente en
`ollama list` (prioriza `HADES-AUTO` y `qwen2.5:7b` si existen).

**Override manual** (solo si Ollama está en otra máquina/puerto):
```bash
export HADES_OLLAMA_URL="http://192.168.1.50:11434"
python3 hades_local.py status
```

Si el modelo tarda o quieres forzar uno pequeño, edita `hades_local.py`:
```python
HADES_MODEL = "qwen2.5:3b"   # o el modelo que hayas descargado
```

### Paso 7 — Verificar que todo funciona

```bash
python3 hades_local.py status
```

Deberías ver algo como esto:

```
══════════════ HADES STATUS ══════════════
  Sistema OS    : KALI
  Ollama modelo : HADES-AUTO
  Herramientas  : 23 detectadas
  PID agente    : No activo
  Ollama URL    : http://localhost:11434/api/generate
  Log           : /home/usuario/.hades_local.log
  Reportes      : /home/usuario/hades_reports
══════════════════════════════════════════
```

> Si `Ollama modelo` muestra `NO DISPONIBLE`, revisa el Paso 4 y 6.

```bash
# Probar conectividad con Ollama directamente:
curl http://localhost:11434/api/tags
# Debe devolver un JSON con la lista de modelos
```

---

## Uso

### Shell interactivo

```bash
python3 hades_local.py start
```

Abre un shell con el prompt `HADES@sistema ▶` desde donde puedes ejecutar todos los comandos de forma interactiva.

### Comandos directos desde terminal

```bash
# Ver estado del agente y herramientas detectadas
python3 hades_local.py status
python3 hades_local.py tools

# Escaneo rápido de un host (top 1000 puertos)
python3 hades_local.py scan 192.168.1.1

# Reconocimiento completo con análisis IA
python3 hades_local.py recon 192.168.1.1

# Auditoría completa automática de toda una red (comando estrella)
python3 hades_local.py fullaudit 192.168.1.0/24

# Auditoría por controles ISO 27001
python3 hades_local.py audit 192.168.1.1

# Análisis forense de archivo (.pcap, .hash, binarios)
python3 hades_local.py analyze captura.pcap

# Detener el modo autónomo si está corriendo en background
python3 hades_local.py stop
```

### Comandos Red Team (Kali / Parrot / Purple — HADES FREE)

```bash
# OSINT sobre un objetivo
python3 hades_local.py osint example.com

# Kill chain completo automatizado (6 fases)
python3 hades_local.py killchain 192.168.1.10
python3 hades_local.py killchain example.com --external   # objetivo externo

# Explotar con Metasploit (IA sugiere el módulo)
python3 hades_local.py exploit 192.168.1.10
python3 hades_local.py exploit 192.168.1.10 --module exploit/windows/smb/ms17_010_eternalblue

# Post-explotación local (SUID, sudo, crons, Docker...)
python3 hades_local.py post

# Ataque de contraseñas (hydra)
python3 hades_local.py pwdattack 192.168.1.10 ssh
python3 hades_local.py pwdattack 192.168.1.10 ftp --users users.txt --passwords rockyou.txt

# Ataque web completo (sqlmap + nuclei + ffuf + nikto)
python3 hades_local.py webattack http://192.168.1.10

# Ataque WiFi completo (monitor → handshake → cracking)
python3 hades_local.py wifiattack wlan0

# Capturar credenciales con Responder
python3 hades_local.py capture eth0
python3 hades_local.py capture eth0 --duration 600

# Movimiento lateral (pass-the-hash o contraseña)
python3 hades_local.py lateral 192.168.1.20 administrator --password 'P@ssw0rd'
python3 hades_local.py lateral 192.168.1.20 administrator --hash aad3b435b51404eeaad3b435b51404ee:31d6...

# Persistencia (MITRE ATT&CK)
python3 hades_local.py persist cron      # T1053 — cron job
python3 hades_local.py persist service   # T1543 — systemd service
python3 hades_local.py persist bashrc    # T1546 — .bashrc
```

> Estos comandos imprimen un aviso y terminan si se ejecutan en un SO no compatible (Ubuntu, Debian, Arch, etc.). Actualiza a **HADES CORE** o **HADES PRO** para eliminar esta restricción.

### Comandos disponibles en el shell interactivo

| Comando | Disponibilidad | Descripción |
|---------|---------------|-------------|
| `scan <ip>` | Todos | Escaneo rápido de los 1000 puertos más comunes |
| `recon <ip>` | Todos | Reconocimiento completo con análisis IA |
| `fullaudit <red/CIDR>` | Todos | Auditoría automática completa con reporte Markdown |
| `audit <ip>` | Todos | Auditoría por controles ISO 27001 (Anexo A) |
| `analyze <archivo>` | Todos | Análisis forense de .pcap, .hash, binarios |
| `ask <pregunta>` | Todos | Consulta libre al modelo IA + ejecución sugerida |
| `tools` | Todos | Lista herramientas detectadas en el sistema |
| `findings` | Todos | Ver hallazgos acumulados en la sesión |
| `osint <objetivo>` | Kali/Parrot/Purple | OSINT completo |
| `enumsmb <ip>` | Kali/Parrot/Purple | Enumeración SMB/Samba |
| `webattack <url>` | Kali/Parrot/Purple | Ataque web completo |
| `pwdattack <ip> <svc>` | Kali/Parrot/Purple | Ataque de contraseñas |
| `crackhash <archivo>` | Kali/Parrot/Purple | Cracking de hashes |
| `exploit <ip>` | Kali/Parrot/Purple | Explotación con Metasploit |
| `post` | Kali/Parrot/Purple | Post-explotación local |
| `lateral <ip> <user>` | Kali/Parrot/Purple | Movimiento lateral |
| `persist <método>` | Kali/Parrot/Purple | Persistencia (cron/service/bashrc) |
| `wifi <iface>` | Kali/Parrot/Purple | Ataque WiFi completo |
| `capture <iface>` | Kali/Parrot/Purple | Captura de credenciales |
| `killchain <ip>` | Kali/Parrot/Purple | Kill chain automatizado 6 fases |
| `clear` | Todos | Limpiar pantalla |
| `help` | Todos | Mostrar ayuda completa |
| `exit` | Todos | Salir del shell |

---

## Flujo de auditoría completa (`fullaudit`)

Cuando ejecutas `fullaudit 192.168.1.0/24`, HADES realiza este flujo automáticamente:

```
FASE 1 — Descubrimiento
  └─ nmap -sn → detecta todos los hosts activos en la red

FASE 2 — Por cada host encontrado:
  ├─ nmap -sV -sC -p- → puertos abiertos y versiones de servicios
  ├─ nmap --script vuln → detección de CVEs conocidos
  ├─ nikto → auditoría de servicios web HTTP/HTTPS
  ├─ openssl → verificación de certificados SSL/TLS
  └─ HADES-IA → análisis de riesgo (BAJO/MEDIO/ALTO/CRÍTICO)

FASE 3 — Reporte final
  ├─ Tabla de riesgos por host
  ├─ Resumen ejecutivo para CISO
  └─ Archivo .md guardado en ~/hades_reports/
```

---

## Ejemplo de reporte generado

```markdown
# HADES — Informe de Seguridad
**Red auditada:** `192.168.1.0/24`
**Fecha:** 2026-04-26 20:45:00

## Host: `192.168.1.1`
| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22/tcp | ssh      | Dropbear sshd 2019.78 |
| 80/tcp | http     | micro_httpd |
| 443/tcp | ssl/http | micro_httpd |

### Análisis HADES-IA
**Riesgo: 🟠 ALTO**
El certificado SSL venció en junio 2025...

## Tabla de Riesgos
| IP | Puertos Abiertos | CVEs | Riesgo |
|----|-----------------|------|--------|
| `192.168.1.1`  | 4 | Ninguno          | 🟠 ALTO    |
| `192.168.1.10` | 3 | CVE-2021-44228   | 🔴 CRÍTICO |
```

---

## Modelos Ollama recomendados

| Modelo | RAM mínima | Velocidad | Calidad | Comando |
|--------|-----------|-----------|---------|---------|
| `qwen2.5:3b` | 4 GB | ⚡⚡⚡ | ⭐⭐⭐ | `ollama pull qwen2.5:3b` |
| `qwen2.5:7b` | 8 GB | ⚡⚡ | ⭐⭐⭐⭐ | `ollama pull qwen2.5:7b` |
| `llama3` | 8 GB | ⚡⚡ | ⭐⭐⭐⭐ | `ollama pull llama3` |
| `dolphin3` | 8 GB | ⚡ | ⭐⭐⭐⭐⭐ | `ollama pull dolphin3` |
| `HADES-AUTO` | 8 GB | ⚡⚡ | ⭐⭐⭐⭐⭐ | `ollama pull HADES-AUTO` |

> `HADES-AUTO` es el modelo optimizado específicamente para análisis de seguridad. Si tu equipo tiene menos de 8 GB de RAM disponibles, usa `qwen2.5:3b`.

---

## Compatibilidad de herramientas por distro

### Herramientas básicas (disponibles en cualquier SO compatible)

| Herramienta | Kali | Parrot | Purple | Ubuntu | Debian |
|-------------|------|--------|--------|--------|--------|
| nmap | ✅ incluido | ✅ incluido | ✅ incluido | ✅ apt | ✅ apt |
| nikto | ✅ incluido | ✅ incluido | ✅ apt | ✅ apt | ✅ apt |
| tshark | ✅ incluido | ✅ incluido | ✅ apt | ✅ apt | ✅ apt |
| john | ✅ incluido | ✅ incluido | ✅ apt | ✅ apt | ✅ apt |
| hashcat | ✅ incluido | ✅ incluido | ✅ apt | ✅ apt | ✅ apt |

### Herramientas Red Team (activas sólo en Kali / Parrot / Purple en FREE)

| Herramienta | Kali | Parrot | Purple | Ubuntu/Debian |
|-------------|------|--------|--------|---------------|
| metasploit | ✅ incluido | ✅ incluido | ✅ incluido | ⚠️ manual |
| aircrack-ng | ✅ incluido | ✅ incluido | ✅ apt | ✅ apt |
| hydra | ✅ incluido | ✅ incluido | ✅ apt | ✅ apt |
| responder | ✅ incluido | ✅ incluido | ✅ pip | ⛔ no disponible en FREE |
| sqlmap | ✅ incluido | ✅ incluido | ✅ pip | ⛔ no disponible en FREE |
| nuclei | ✅ go install | ✅ go install | ✅ go install | ⛔ no disponible en FREE |
| ffuf | ✅ apt | ✅ apt | ✅ apt | ⛔ no disponible en FREE |
| netexec | ✅ pip | ✅ pip | ✅ pip | ⛔ no disponible en FREE |
| impacket | ✅ pip | ✅ pip | ✅ pip | ⛔ no disponible en FREE |
| theHarvester | ✅ incluido | ✅ incluido | ✅ pip | ⛔ no disponible en FREE |

> `install_tools.sh` instala automáticamente las herramientas disponibles vía `apt` y `pip`.

---

## Configuración en Windows + WSL

Si usas Windows con WSL, Ollama corre en Windows y HADES en WSL.
**Desde la v2.1.0 HADES detecta el host Windows automáticamente** (vía el
`nameserver` de `/etc/resolv.conf`). Solo necesitas un ajuste en Windows:

**En PowerShell (Windows) — una sola vez:**
```powershell
# Permitir que Ollama escuche en todas las interfaces (incluida WSL)
[System.Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0", "User")
# Reiniciar Ollama desde el ícono en la barra de tareas para que tome el cambio
```

**En WSL — simplemente verifica:**
```bash
python3 hades_local.py status
# Ollama URL debe mostrar la IP del host Windows automáticamente
```

Si por una configuración de red atípica no lo detecta, fuérzalo a mano:
```bash
IP=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
export HADES_OLLAMA_URL="http://$IP:11434"
python3 hades_local.py status
```

---

## Modo Pendrive — HADES portátil

El script `build_pendrive.sh` empaqueta HADES completo (agente + Ollama + modelos) en un pendrive USB para usar en cualquier Linux sin instalación:

```bash
# Construir en ~/hades_pendrive/ (para después copiar al USB)
bash build_pendrive.sh

# O construir directamente en el pendrive montado
bash build_pendrive.sh /mnt/usb
```

El pendrive incluye:
- `launch.sh` — Lanzador inteligente (detecta el mejor formato)
- `hades.sh` — Script bash portable (máxima compatibilidad)
- `hades.bin` — Binario compilado con PyInstaller (x86_64)
- `ollama` — Motor IA portable sin instalación
- `models/` — Modelos descargados

Para usar en cualquier equipo Linux:
```bash
chmod +x launch.sh
./launch.sh start
```

---

## Desinstalación

Para eliminar HADES del equipo de forma limpia, usa el script incluido:

```bash
cd ~/hades_local        # o donde lo hayas clonado
bash uninstall.sh
```

Modos:

```bash
bash uninstall.sh            # interactivo: pregunta qué borrar
bash uninstall.sh --yes      # borra el agente sin preguntar
                             # (conserva reportes y Ollama)
bash uninstall.sh --purge    # borra TODO: agente + reportes
                             # + modelos + Ollama
```

El desinstalador detiene el agente, borra logs/PID, el comando global,
el directorio del agente y (opcionalmente) los reportes y Ollama.

---

## Solución de problemas

**`Ollama modelo: NO DISPONIBLE`**
```bash
# 1. Verificar que Ollama corre y tiene al menos un modelo
curl http://localhost:11434/api/tags     # debe devolver JSON con modelos
ollama list

# 2. Si no responde, iniciar Ollama y descargar un modelo
ollama serve &
ollama pull llama3

# 3. Ver qué URL detectó HADES (debe apuntar a tu Ollama)
python3 hades_local.py status

# 4. Si Ollama está en otra máquina/puerto, fuérzalo:
export HADES_OLLAMA_URL="http://IP_DE_OLLAMA:11434"
python3 hades_local.py status
```

**`nmap: command not found` u otras herramientas faltantes**
```bash
sudo bash install_tools.sh
```

**El modelo tarda mucho o da timeout**
Edita `hades_local.py` y usa un modelo más pequeño:
```python
HADES_MODEL    = "qwen2.5:3b"
FALLBACK_MODEL = "qwen2.5:3b"
OLLAMA_TIMEOUT = 600  # aumentar si el equipo es lento
```

**Permisos denegados en escaneo de red**
Algunos comandos de nmap requieren privilegios de red:
```bash
sudo python3 hades_local.py fullaudit 192.168.1.0/24
```

---

## Changelog

### v2.1.0-REDTEAM (2026-05-17)
- **Autodetección de Ollama**: ya no hay que editar `OLLAMA_URL` a mano. Funciona automáticamente en Linux nativo (Kali/Parrot/Purple/Ubuntu/Debian), WSL2 y VMs (VirtualBox/VMware NAT). Soporta override con `HADES_OLLAMA_URL`.
- **Nuevo `uninstall.sh`**: desinstalación limpia con modos `--yes` y `--purge`.
- `build_pendrive.sh` ahora pasa la URL por variable de entorno (sin parchear el fuente).
- Versionado unificado a `2.1.0-REDTEAM` en todo el proyecto.
- README, manual y landing actualizados a la autodetección.

### v2.0.0-REDTEAM
- Edición Red Team: killchain, exploit, post-explotación, WiFi, pivoting.

### v1.1.0
- Versión base: auditoría, recon, fullaudit, modo pendrive.

---

## Aviso legal

> **HADES-LOCAL está diseñado exclusivamente para auditorías de seguridad autorizadas.**
>
> El uso de esta herramienta en sistemas sin autorización expresa es ilegal en la mayoría de jurisdicciones, incluyendo Chile (Ley 21.459 de Delitos Informáticos) y a nivel internacional (Convenio de Budapest).
>
> El autor no se hace responsable del uso indebido de este software. Úsalo únicamente en sistemas de tu propiedad o con autorización escrita del propietario.

---

## Autor

**Fabián Hormaz ábal**
CTO — Servicios Integrales Empresariales SPA
Especialista en Ciberseguridad | Auditor ISO 27001
Punta Arenas, Chile

[@LordHades268](https://x.com/LordHades268)

---

## Licencia

MIT License — ver [LICENSE](LICENSE)
