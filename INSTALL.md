# 📦 Guía de Instalación - PCAP Analyzer

## Opción 1: Instalación Rápida Automática (RECOMENDADO)

### Windows

1. **Descarga el proyecto:**
   - Descarga el ZIP desde el repositorio
   - O clona: `git clone <url-del-repo>`
   - Extrae en una carpeta, ejemplo: `C:\Users\TUUSUARIO\Desktop\pcap-analyzer`

2. **Ejecuta el script de instalación:**
   ```bash
   cd C:\Users\TUUSUARIO\Desktop\pcap-analyzer
   setup.bat
   ```

3. **¡Listo!** La aplicación se ejecutará automáticamente

### macOS / Linux

1. **Descarga el proyecto:**
   ```bash
   git clone <url-del-repo>
   cd pcap-analyzer
   ```

2. **Instala dependencias del sistema (requeridas para Scapy):**

   **Ubuntu/Debian:**
   ```bash
   sudo apt update
   sudo apt install libpcap-dev
   ```

   **Fedora/CentOS/RHEL:**
   ```bash
   sudo dnf install libpcap-devel
   ```

   **macOS:**
   ```bash
   brew install libpcap
   ```

3. **Da permisos de ejecución al script:**
   ```bash
   chmod +x setup.sh
   ```

4. **Ejecuta el script de instalación:**
   ```bash
   ./setup.sh
   ```

5. **¡Listo!** La aplicación se ejecutará automáticamente

---

## Opción 2: Instalación Manual

### Paso 1: Verificar Python

#### Windows (PowerShell)
```powershell
python --version
```

#### macOS/Linux (Terminal)
```bash
python3 --version
```

**Si no aparece versión:**
- **Windows:** Descarga desde https://www.python.org/downloads/ (marca "Add Python to PATH")
- **macOS:** `brew install python3`
- **Linux:** `sudo apt install python3 python3-pip`

### Paso 2: Crear Entorno Virtual

#### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

#### macOS/Linux (Terminal)
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**IMPORTANTE en Linux:** Antes de instalar dependencias, asegúrate de que libpcap está instalado:
- **Ubuntu/Debian:** `sudo apt install libpcap-dev`
- **Fedora/CentOS:** `sudo dnf install libpcap-devel`
- **macOS:** `brew install libpcap`

### Paso 3: Instalar Dependencias
ython -m pip install -r requirements.txt
```

Para asegurar compatibilidad:
- **Windows:** `python -m pip install -r requirements.txt`
- **Linux/macOS:** `python3 -m pip install -r requirements.txt`

#### Opción B: Instalar manualmente
```bash
python -m pip install -r requirements.txt
```

#### Opción B: Instalar manualmente
```bash
pip install scapy==2.7.0
```

### Paso 4: Verificar Instalación

**En Linux/macOS usa `python3`:**
```bash
python3 -c "import scapy; print('✓ Scapy ' + scapy.__version__)"
```

```bash
python -c "import scapy; print('✓ Scapy ' + scapy.__version__)"
```

Deberías ver algo como:
```
✓ Scapy 2.7.0
```

### Paso 5: Ejecutar la Aplicación

```bash
python pcap_analyzer.py
```

---

## 🔧 Solución de Problemas

### Error: `python: command not found` (macOS/Linux)
**Solución:**
```bash
# Usa python3 en lugar de python
python3 pcap_analyzer.py
```

### Error: `ModuleNotFoundError: No module named 'scapy'`
**Solución:**
```bash
# Verifica que el venv está activado
# Windows: .\.venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate

# Reinstala scapy
pip install --upgrade scapy
```

### Error: `_tkinter.TclError`
**Solución:**
```bash
# Reinstala Python con tkinter
# Windows: Desinstala Python, reinstala marcando "tcl/tk and IDLE"
# macOS: brew install python-tk
# Linux: sudo apt install python3-tk
```

### El venv no se activa
**Solución - Windows (si tienes error de ejecución):**
```powershell
# Ejecuta PowerShell como administrador
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Luego intenta activar:
.\.venv\Scripts\Activate.ps1
```

### Scapy no encuentra interfaces de red
**Solución - Windows:**
- Instala **Npcap** desde: https://npcap.com/download.html
- O instala **Wireshark** (incluye Npcap)

---

## 📂 Estructura Esperada Después de Instalación

```
pcap-analyzer/
├── pcap_analyzer.py          ✓ Mantener
├── README.md                 ✓ Mantener
├── INSTALL.md                ✓ Mantener
├── requirements.txt          ✓ Mantener
├── setup.bat                 ✓ Mantener (Windows)
├── setup.sh                  ✓ Mantener (macOS/Linux)
├── .gitignore                ✓ Mantener
│
├── .venv/                    ✓ CREADO AUTOMATICAMENTE
│   ├── Scripts/ (Windows)       o
│   └── bin/    (macOS/Linux)
│
└── (Otros archivos opcionales)
```

---

## ✅ Checklist Final

- [ ] Python 3.10+ instalado
- [ ] Proyecto descargado en carpeta
- [ ] Entorno virtual creado
- [ ] Entorno virtual activado
- [ ] Scapy instalado
- [ ] `python -c "import scapy"` funciona
- [ ] `python pcap_analyzer.py` abre la GUI
- [ ] Tienes un archivo `.pcap` de prueba (opcional)

---

## 🎯 Tu Primer Análisis

1. Abre PCAP Analyzer
2. Haz clic en "Explorar" 
3. Selecciona un archivo `.pcap` o `.pcapng`
4. Haz clic en "Analizar"
5. Espera a que complete
6. Haz clic en "Abrir reporte" para ver el análisis detallado

---

## 📚 Ejemplos de Archivos PCAP

Si no tienes un archivo PCAP, puedes:
1. Usar ejemplos públicos: https://www.pcapng.org/
2. Capturar tu propio tráfico con Wireshark
3. Usar herramientas como `tcpdump` (Linux/macOS)

---

## 🆘 Soporte

Si tienes problemas:
1. Lee el README.md
2. Busca tu error en esta guía
3. Verifica que Python 3.10+ está instalado
4. Intenta en una carpeta sin espacios en la ruta

---

**¡Listo para analizar tráfico de red! 🔍**
