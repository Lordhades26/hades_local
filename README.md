# 🔴 HADES-LOCAL — Autonomous Security Agent

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

![Version](https://img.shields.io/badge/version-1.1.0-red)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL-lightgrey)
![AI](https://img.shields.io/badge/AI-Ollama%20Local-orange)

*Agente autónomo de ciberseguridad impulsado por IA local. Sin cloud. Sin API keys. Sin límites.*

</div>

---

## ¿Qué es HADES-LOCAL?

HADES-LOCAL es un agente de seguridad autónomo que combina herramientas de hacking ético con inteligencia artificial local (Ollama) para realizar auditorías de red, análisis de vulnerabilidades y generación de reportes de forma completamente automática.

**No requiere internet para operar.** La IA corre 100% en tu máquina.

### Características principales

- **Auditoría automática completa** — Descubre hosts, escanea puertos, detecta CVEs y genera reporte con un solo comando
- **Análisis IA por host** — Cada dispositivo encontrado es analizado por el modelo de lenguaje local
- **Compatible con cualquier Linux** — Funciona en Kali, Parrot, Ubuntu, Debian, WSL
- **Detección automática de herramientas** — Si tienes nmap, nikto, metasploit, los usa. Si no, opera con lo que hay
- **Reportes Markdown profesionales** — Guardados automáticamente en `~/hades_reports/`
- **Shell interactivo** — Interfaz de comandos con colores y prompt dedicado
- **Modo autónomo** — Escanea la red cada 30 minutos sin intervención humana

---

## Requisitos

### Obligatorios
- Python 3.8 o superior
- [Ollama](https://ollama.com) instalado (local o en red)
- Al menos un modelo descargado en Ollama

### Opcionales (amplían capacidades)
- `nmap` — Reconocimiento y vulnerabilidades *(altamente recomendado)*
- `nikto` — Auditoría de servicios web
- `tshark` / `wireshark` — Análisis de tráfico
- `john` / `hashcat` — Cracking de hashes
- `aircrack-ng` — Auditoría WiFi
- `metasploit-framework` — Explotación

---

## Instalación rápida

### 1. Clonar el repositorio

```bash
git clone https://github.com/LordHades268/hades-local.git
cd hades-local
```

### 2. Instalar herramientas de seguridad (Ubuntu/Debian)

```bash
chmod +x scripts/install_tools.sh
sudo ./scripts/install_tools.sh
```

### 3. Instalar y configurar Ollama

```bash
# Instalar Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Iniciar el servicio
ollama serve &

# Descargar el modelo HADES (o cualquier otro)
ollama pull llama3
```

### 4. Configurar HADES

Edita la línea `OLLAMA_URL` en `hades_local.py`:

```python
# Si Ollama está en la misma máquina:
OLLAMA_URL = "http://localhost:11434/api/generate"

# Si Ollama está en Windows y usas WSL:
OLLAMA_URL = "http://172.27.64.1:11434/api/generate"
# (reemplaza la IP con la de tu adaptador vEthernet WSL)
```

Para encontrar la IP de Windows desde WSL:
```bash
cat /etc/resolv.conf | grep nameserver | awk '{print $2}'
# o desde PowerShell:
# (Get-NetIPAddress -InterfaceAlias "vEthernet (WSL (Hyper-V firewall))" -AddressFamily IPv4).IPAddress
```

### 5. Verificar instalación

```bash
python3 hades_local.py status
```

Deberías ver:
```
══════════════ HADES STATUS ══════════════
  Sistema OS    : UBUNTU
  Ollama modelo : HADES-AUTO
  Herramientas  : 23 detectadas
  PID agente    : No activo
══════════════════════════════════════════
```

---

## Uso

### Shell interactivo

```bash
python3 hades_local.py start
```

Abre un shell dedicado con prompt `HADES@sistema ▶`

### Comandos directos desde terminal

```bash
# Ver estado del agente
python3 hades_local.py status

# Ver herramientas detectadas
python3 hades_local.py tools

# Escaneo rápido de un host
python3 hades_local.py scan 192.168.1.1

# Reconocimiento completo con análisis IA
python3 hades_local.py recon 192.168.1.0/24

# Auditoría completa automática (el comando estrella)
python3 hades_local.py fullaudit 192.168.1.0/24

# Auditoría ISO 27001
python3 hades_local.py audit 192.168.1.1

# Análisis forense de archivo
python3 hades_local.py analyze captura.pcap

# Modo autónomo (escanea cada 30 minutos)
python3 hades_local.py start --auto

# Detener modo autónomo
python3 hades_local.py stop
```

---

## Comandos del shell interactivo

Una vez dentro del shell (`python3 hades_local.py start`):

| Comando | Descripción |
|---------|-------------|
| `scan <ip>` | Escaneo rápido de los 1000 puertos más comunes |
| `recon <ip o red>` | Reconocimiento completo con análisis IA |
| `fullaudit <red/CIDR>` | Auditoría automática completa con reporte |
| `audit <ip>` | Auditoría por controles ISO 27001 |
| `analyze <archivo>` | Análisis forense de .pcap, .hash, binarios |
| `ask <pregunta>` | Consulta libre al modelo de IA |
| `tools` | Lista herramientas detectadas en el sistema |
| `findings` | Ver hallazgos acumulados en la sesión |
| `clear` | Limpiar pantalla |
| `help` | Mostrar ayuda |
| `exit` | Salir del shell |

---

## Flujo de auditoría completa (`fullaudit`)

Cuando ejecutas `fullaudit 192.168.1.0/24`, HADES realiza este flujo automáticamente:

```
FASE 1 — Descubrimiento
  └─ nmap -sn → detecta todos los hosts activos

FASE 2 — Por cada host encontrado:
  ├─ nmap -sV -sC -p- → puertos y versiones de servicios
  ├─ nmap --script vuln → detección de CVEs conocidos
  ├─ nikto → auditoría de servicios web HTTP/HTTPS
  ├─ openssl → verificación de certificados SSL/TLS
  └─ HADES-IA → análisis y nivel de riesgo (BAJO/MEDIO/ALTO/CRÍTICO)

FASE 3 — Reporte
  ├─ Tabla de riesgos por host
  ├─ Resumen ejecutivo para CISO
  └─ Archivo .md guardado en ~/hades_reports/
```

---

## Ejemplo de reporte generado

```markdown
# HADES — Informe de Seguridad
**Red auditada:** 192.168.1.0/24
**Fecha:** 2026-04-06 20:45:00

## Host: 192.168.1.1
| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22/tcp | ssh | Dropbear sshd 2019.78 |
| 80/tcp | http | micro_httpd |
| 443/tcp | ssl/http | micro_httpd |

### Análisis HADES-IA
Riesgo: 🟠 ALTO
El certificado SSL venció en junio 2025...
[...]

## Tabla de Riesgos
| IP | Puertos | CVEs | Riesgo |
|----|---------|------|--------|
| 192.168.1.1 | 4 | Ninguno | 🟠 ALTO |
| 192.168.1.10 | 3 | CVE-2021-xxxx | 🔴 CRÍTICO |
```

---

## Instalación de Ollama en Windows con WSL

Si usas Windows con WSL, Ollama puede correr en Windows y HADES en WSL. Pasos:

**En PowerShell (Windows):**
```powershell
# Descargar e instalar Ollama
# https://ollama.com/download/windows

# Permitir conexiones desde WSL
$env:OLLAMA_HOST = "0.0.0.0"
ollama serve

# En otra ventana, descargar modelo
ollama pull llama3
```

**En WSL:**
```bash
# Obtener IP de Windows
IP=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
echo $IP

# Probar conexión
curl http://$IP:11434/api/tags

# Editar HADES con la IP correcta
sed -i "s|http://localhost:11434|http://$IP:11434|g" hades_local.py
```

---

## Modelos Ollama recomendados

| Modelo | RAM requerida | Velocidad | Calidad |
|--------|--------------|-----------|---------|
| `qwen2.5:3b` | 4 GB | ⚡⚡⚡ | ⭐⭐⭐ |
| `llama3` | 8 GB | ⚡⚡ | ⭐⭐⭐⭐ |
| `qwen2.5:7b` | 8 GB | ⚡⚡ | ⭐⭐⭐⭐ |
| `HADES-AUTO` | 8 GB | ⚡⚡ | ⭐⭐⭐⭐⭐ |
| `dolphin3` | 8 GB | ⚡ | ⭐⭐⭐⭐⭐ |

Para hardware limitado (< 8 GB RAM):
```bash
ollama pull qwen2.5:3b
# Editar hades_local.py:
# HADES_MODEL = "qwen2.5:3b"
```

---

## Compatibilidad de herramientas por distro

| Herramienta | Kali | Parrot | Ubuntu | Debian |
|-------------|------|--------|--------|--------|
| nmap | ✅ | ✅ | ✅ apt | ✅ apt |
| metasploit | ✅ | ✅ | ⚠️ manual | ⚠️ manual |
| nikto | ✅ | ✅ | ✅ apt | ✅ apt |
| aircrack-ng | ✅ | ✅ | ✅ apt | ✅ apt |
| tshark | ✅ | ✅ | ✅ apt | ✅ apt |
| john | ✅ | ✅ | ✅ apt | ✅ apt |
| hashcat | ✅ | ✅ | ✅ apt | ✅ apt |

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

🐦 [@LordHades268](https://x.com/LordHades268)

---

## Licencia

MIT License — ver [LICENSE](LICENSE)
