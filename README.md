# 🔍 PCAP Analyzer - Network Forensics Engine
**Herramienta de Análisis Forense en Tiempo Real de Capturas de Tráfico de Red**

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![License](https://img.shields.io/badge/License-MIT-yellow) ![Scapy](https://img.shields.io/badge/Scapy-2.7.0-green) ![Status](https://img.shields.io/badge/Status-Production-brightgreen)

[!IMPORTANT]
> **⚠️ AVISO LEGAL Y ÉTICO / LEGAL & ETHICAL DISCLAIMER**
> 
> **ES:** No analizar tráfico de red de terceros sin autorización previa explícita. Esta herramienta ha sido creada exclusivamente con fines educativos, de investigación forense autorizada y análisis de seguridad en entornos controlados.
> 
> **EN:** Do not analyze third-party network traffic without explicit prior authorization. This tool is created for educational purposes, authorized forensic investigation, and security analysis in controlled environments only.

---

## 🎯 Descripción General

**PCAP Analyzer** es una herramienta profesional de análisis forense de red que detecta patrones anómalos, ataques activos y comportamientos sospechosos en capturas de tráfico PCAP/PCAPNG. Utiliza heurística avanzada basada en estadística y machine learning patterns para identificar:

- **Beaconing:** Comunicación periódica con servidores C2 (Command & Control)
- **DNS Tunneling:** Tunelización de datos maliciosos sobre DNS
- **Port Scanning:** Exploración sistemática de puertos en búsqueda de vulnerabilidades
- **SYN Floods:** Ataques DDoS basados en inundación de paquetes SYN
- **ARP Spoofing:** Ataques Man-in-the-Middle mediante suplantación ARP
- **TCP Retransmissions:** Análisis granular de retransmisiones por puerto y flujo
- **Data Exfiltration:** Detección de transferencias masivas de datos sospechosas
- **DGA/DNS Masivo:** Identificación de algoritmos generadores de dominios
- **ICMP Floods:** Ataques de negación de servicio mediante ICMP

---

## ✨ Características Destacadas

### 🔬 Análisis Profundo por Flujo TCP
- Desglose **origen:puerto → destino:puerto**
- Conteo de paquetes y volumen de datos por conexión
- Detección de retransmisiones granulares
- Identificación de patrones de exfiltración

### 📊 Estadísticas Completas
- Paquetes totales procesados
- IPs únicas identificadas
- Conexiones TCP activas
- Consultas DNS y dominios únicos
- Retransmisiones TCP detalladas

### 🎨 Interfaz Gráfica Moderna
- Tema oscuro profesional (cybersecurity aesthetic)
- Dos tabs: Consola de análisis + Hallazgos detallados
- Barra de progreso en tiempo real
- Código HTML interactivo para reportes

### 📄 Generación de Reportes
- Reporte HTML profesional con gráficos CSS
- Almacenamiento automático en carpeta Descargas
- Clasificación de riesgos: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Recomendaciones accionables para cada hallazgo

---

## 🛠️ Instalación y Uso

### Requisitos Previos
- **Python 3.10+** (se recomienda 3.11 o superior)
- **pip** (gestor de paquetes de Python)
- Sistema operativo: Windows, macOS o Linux

### Opción 1: En tu PC original (con el venv existente)

Si **ya tienes el proyecto configurado:**

```bash
# Navega a la carpeta del proyecto
cd "c:\Users\OneDrive\pcap analyzer"
# Ejecuta la aplicación
python setup.sh
```
# Ejecuta la aplicación
python pcap_analyzer.py
```

### Opción 2: Descargar en OTRA PC (sin venv)

#### Paso 1: Descargar y preparar archivos

```bash
# Clona o descarga el proyecto en la nueva PC
git clone <repo-url>
# O descarga el ZIP y extrae en una carpeta, ejemplo:
# C:\Users\TUUSUARIO\Desktop\pcap-analyzer
```

#### Paso 2: Crear un entorno virtual nuevo

```bash
# Navega a la carpeta del proyecto
cd "C:\Users\TUUSUARIO\Desktop\pcap-analyzer"

# Crea un nuevo entorno virtual
python -m venv .venv

# Activa el entorno (Windows)
.\.venv\Scripts\Activate.ps1

# Activa el entorno (macOS/Linux)
source .venv/bin/activate
```

#### Paso 3: Instalar dependencias

```bash
# Instala scapy (única dependencia externa)
pip install scapy

# Verifica que scapy está instalado
pip list | grep scapy
```

#### Paso 4: Ejecutar la aplicación

```bash
# Windows
python pcap_analyzer.py

# macOS/Linux
python3 pcap_analyzer.py
```

---

## 📖 Guía de Uso Rápido

### 1. **Cargar un archivo PCAP**
- Haz clic en el botón **"Explorar"** 
- Selecciona un archivo `.pcap`, `.pcapng` o `.cap`

### 2. **Iniciar análisis**
- Haz clic en **"▶ Analizar"**
- La barra de progreso mostrará el estado en tiempo real
- Los dos tabs se llenarán con:
  - **Tab Consola:** Resumen ejecutivo y estadísticas
  - **Tab Hallazgos:** Análisis detallado de cada amenaza

### 3. **Generar reporte HTML**
- Al completarse el análisis, se genera automáticamente `pcap_report_YYYYMMDD_HHMMSS.html`
- Se guarda en tu carpeta **Descargas**
- Haz clic en **"↗ Abrir reporte"** para visualizarlo en el navegador

### 4. **Interpretar los resultados**

#### Ejemplo: Retransmisiones TCP con detalle de puertos
```
[HIGH] Alto número de retransmisiones TCP

Ejemplos detectados:
  • 192.168.1.100:52341 → 10.0.0.5:443  |  15 retransmisiones
  • 192.168.1.101:49999 → 10.0.0.5:3306  |  8 retransmisiones
```

#### Ejemplo: Top Conexiones TCP
```
── TOP CONEXIONES TCP (por volumen) ────────────────
  192.168.1.100:52341 → 10.0.0.5:443     1245 paqts   4520.5 KB
  192.168.1.102:60123 → 8.8.8.8:53         856 paqts    125.3 KB
```

---

## 🔐 Conceptos de Ciberseguridad

### Beaconing (C2 Communication)
Un implante de malware que se reporta periódicamente a su servidor de control. **PCAP Analyzer** detecta comunicación con:
- **Matriz de variación < 18%:** Comunicación extremadamente regular
- **Intervalo 4-900 segundos:** Patrón típico de RATs y botnets

### DNS Tunneling (Data Exfiltration)
Abuso del protocolo DNS para ocultar datos. Se detecta mediante:
- **Entropía de Shannon > 3.6 bits:** Aleatorización sospechosa
- **Dominios > 52 caracteres:** Codificación Base64/Hex dentro de subdominios

### Port Scanning (Reconnaissance)
Mapeo de servicios antes de un ataque. Indicador:
- **IP que contacta > 35 puertos distintos:** Patrón de escáner (Nmap, Masscan)

### ARP Spoofing (MITM Attack)
Suplantación de identidad en la red local. Detector:
- **Una IP responde con múltiples MACs:** Intercepción de tráfico

---

## 📊 Estructura de Archivos

```
pcap-analyzer/
├── pcap_analyzer.py          # Aplicación principal
├── README.md                  # Este archivo
├── .venv/                     # Entorno virtual (no incluir en descargas)
│   ├── Scripts/
│   ├── Lib/
│   └── pyvenv.cfg
└── (Archivos .pcap de prueba opcionales)
```

### Archivos a descargar en otra PC
```
✓ pcap_analyzer.py
✓ README.md
✗ .venv/                      (NO incluir, se crea nuevo)
```

---

## 🚀 Comandos Útiles

### Crear captura PCAP en tiempo real (Linux/macOS):
```bash
# Capturar 1000 paquetes de la interfaz eth0
sudo tcpdump -i eth0 -c 1000 -w captura.pcap

# Capturar del puerto 443 (HTTPS)
sudo tcpdump -i eth0 -w https_traffic.pcap port 443
```

### En Windows (requiere Npcap o Wireshark):
```bash
# Usar tshark (incluido en Wireshark)
tshark -i "Ethernet" -c 1000 -w captura.pcap
```

---

## ⚠️ Solución de Problemas

### Error: `ImportError: No module named 'scapy'`
```bash
# Asegúrate de que el venv está activado
.\.venv\Scripts\Activate.ps1

# Reinstala scapy
pip install --upgrade scapy
```

### Error: `_tkinter.TclError: invalid color name`
- Este error ha sido corregido en la última versión
- Si persiste, realiza un `pip install --upgrade scapy`

### Archivo PCAP no se carga
- Verifica que el archivo existe en la ruta especificada
- Asegúrate de que es un archivo válido `.pcap` o `.pcapng`
- Intenta abrirlo primero con Wireshark para validarlo

### La GUI no aparece
- En Linux/macOS, asegúrate de tener X11 o Wayland configurado
- En Windows, verifica que Python de Stack Overflow está instalado con Tkinter

---

## 📋 Checklist de Instalación en Nueva PC

- [ ] Python 3.10+ instalado
- [ ] Carpeta del proyecto descargada
- [ ] Entorno virtual creado (`.venv`)
- [ ] Entorno virtual activado
- [ ] Scapy instalado (`pip install scapy`)
- [ ] Archivo PCAP disponible para análisis
- [ ] Aplicación ejecutada correctamente (`python pcap_analyzer.py`)

---

## 🤝 Soporte y Actualizaciones

Para reportar bugs, sugerencias o mejoras:
1. Verifica que tienes la última versión de Scapy: `pip install --upgrade scapy`
2. Prueba con un PCAP diferente
3. Consulta los archivos `.log` en la carpeta de la aplicación

---

## 📝 Licencia

MIT License - Libre para uso educativo y forense autorizado.

---

## 🎓 Recursos Educativos

- **Scapy Documentation:** https://scapy.readthedocs.io/
- **RFC 8996 (TLS 1.3):** https://tools.ietf.org/html/rfc8996
- **OWASP Network Testing Guide:** https://owasp.org/www-project-web-security-testing-guide/
- **Wireshark User Guide:** https://www.wireshark.org/docs/

---

**Última actualización:** Abril 2026  
**Versión:** 1.0 Production  
**Autor:** Gonzalo (Reto 100 Apps de Ciberseguridad)

---

> ¡Usa esta herramienta de forma responsable y ética! 🔐
