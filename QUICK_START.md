# 🚀 QUICK START - Inicio Rápido

## En tu PC actual (Desarrollador)

### Windows (PowerShell)
```powershell
# Abre PowerShell en carpeta del proyecto
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python pcap_analyzer.py
```

### macOS/Linux (Terminal)
```bash
# Abre Terminal en carpeta del proyecto
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python pcap_analyzer.py
```

---

## Distribuir a OTRA PC

### Opción Fácil: Usar Script Automático ⭐

**Windows:** Envía `pcap_analyzer.py`, `README.md`, `requirements.txt`, `setup.bat`
- En otra PC: Abre PowerShell, ve a carpeta, ejecuta: `setup.bat`

**macOS/Linux:** Envía `pcap_analyzer.py`, `README.md`, `requirements.txt`, `setup.sh`
- En otra PC: Abre Terminal, ve a carpeta, ejecuta: `chmod +x setup.sh && ./setup.sh`

### Opción Manual: Instrucciones Paso a Paso

Ver [INSTALL.md](INSTALL.md)

---

## Verificar Instalación

```bash
python verify_environment.py
```

Debes ver todos los checkmarks (✓) en verde

---

## Documentación Completa

- 📖 [INDEX.md](INDEX.md) - Índice de toda la documentación
- 📋 [INSTALL.md](INSTALL.md) - Guía completa de instalación
- 📘 [README.md](README.md) - Descripción, características, conceptos

---

## Primeros Pasos

1. Asegúrate que se ejecuta: `python pcap_analyzer.py`
2. La GUI debe abrirse
3. Haz clic en "Explorar" 
4. Selecciona un archivo `.pcap` o `.pcapng`
5. Haz clic en "Analizar"
6. ¡Espera a que termine!
7. Haz clic en "Abrir Reporte" para ver los resultados

---

## Ayuda Rápida

| Problema | Solución |
|----------|----------|
| `ModuleNotFoundError: scapy` | `pip install scapy==2.7.0` |
| `ModuleNotFoundError: tkinter` | Ver sección Tkinter en [INSTALL.md](INSTALL.md) |
| `python: command not found` | Usa `python3` en lugar de `python` (macOS/Linux) |
| No veo archivos PCAP | Genera uno: `sudo tcpdump -i eth0 -w test.pcap` |

---

**¡Listo! 🎉**
