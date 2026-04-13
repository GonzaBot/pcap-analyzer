# 📦 DESCARGAR Y DISTRIBUIR - Guía Completa

## ¿Cuáles archivos descargar para otra PC?

### Archivos NECESARIOS ✓ (SIEMPRE descargar)
```
✓ pcap_analyzer.py          (La aplicación principal)
✓ README.md                 (Documentación general)
✓ requirements.txt          (Lista de dependencias)
✓ QUICK_START.md            (Instrucciones rápidas)
✓ INSTALL.md                (Guía de instalación detallada)
```

### Archivos RECOMENDADOS ⭐ (Facilitan mucho la instalación)
```
⭐ setup.bat                (Si la otra PC usa WINDOWS)
⭐ setup.sh                 (Si la otra PC usa macOS/LINUX)
```

### Archivos OPCIONALES (Para referencia)
```
○ INDEX.md                  (Índice de documentación)
○ verify_environment.py     (Script para verificar instalación)
○ .gitignore                (Solo para git)
```

### Archivos a NO descargar ✗ (NO incluyen)
```
✗ .venv/                    (Carpeta del entorno virtual)
✗ __pycache__/              (Archivos compilados)
✗ *.pyc                     (Archivos compilados de Python)
✗ .vscode/                  (Configuración del editor)
✗ .idea/                    (Configuración de IDE)
✗ *.pcap                    (Archivos de prueba)
```

---

## 📋 Paso a Paso: Preparar para Distribuir

### Paso 1: Crear Carpeta para Distribuir
```bash
mkdir pcap-analyzer-v1.0
cd pcap-analyzer-v1.0
```

### Paso 2: Copiar Archivos Necesarios
```bash
# Copiar los archivos obligatorios
cp ../pcap_analyzer.py .
cp ../README.md .
cp ../requirements.txt .
cp ../QUICK_START.md .
cp ../INSTALL.md .

# Copiar scripts de instalación (según SO destino)
cp ../setup.bat .           # Para Windows
cp ../setup.sh .            # Para macOS/Linux

# (OPCIONAL) Copiar verificador
cp ../verify_environment.py .
cp ../INDEX.md .
```

### Paso 3: Comprimir
```bash
# Windows (usa Explorador de Archivos)
# Click derecho > Enviar a > Carpeta comprimida

# macOS/Linux
zip -r pcap-analyzer-v1.0.zip pcap-analyzer-v1.0

# O usar tar
tar -czf pcap-analyzer-v1.0.tar.gz pcap-analyzer-v1.0
```

### Paso 4: Distribuir
- Envía por email, Drive, OneDrive, etc.
- La otra persona extrae el ZIP
- Sigue las instrucciones en QUICK_START.md

---

## 📊 Checklist Antes de Enviar

- [ ] `pcap_analyzer.py` incluido ✓
- [ ] `README.md` incluido ✓
- [ ] `requirements.txt` incluido ✓
- [ ] `QUICK_START.md` incluido ✓
- [ ] `INSTALL.md` incluido ✓
- [ ] `setup.bat` incluido (si va a Windows) ✓
- [ ] `setup.sh` incluido (si va a macOS/Linux) ✓
- [ ] **NO hay** `.venv/` folder ✓
- [ ] **NO hay** `__pycache__/` ✓
- [ ] **NO hay** `.pyc` files ✓
- [ ] Total de archivos: ~8-9 ✓

---

## 🎯 Instrucciones para el DESTINATARIO

### Si Recibe la Carpeta:

1. **Extrae el ZIP**
   ```bash
   # Windows: Click derecho > Extraer todo
   # macOS/Linux: unzip pcap-analyzer-v1.0.zip
   ```

2. **Ejecuta el script de instalación**
   ```bash
   # Windows (PowerShell)
   .\setup.bat

   # macOS/Linux (Terminal)
   chmod +x setup.sh
   ./setup.sh
   ```

3. **¡Listo! La aplicación se abre automáticamente**

---

## 📧 Ejemplo de Email para Enviar

```
Asunto: PCAP Analyzer v1.0 - Herramienta de Análisis de Tráfico

Hola,

Te envío PCAP Analyzer, una herramienta profesional para analizar 
tráfico de red en busca de anomalías de seguridad.

INSTALACIÓN (2 minutos):
1. Extrae el ZIP adjunto
2. Abre PowerShell (Windows) o Terminal (macOS/Linux)
3. Ve a la carpeta extraída
4. Ejecuta: setup.bat (Windows) o ./setup.sh (macOS/Linux)
5. La aplicación se abrirá automáticamente

PRIMEROS PASOS:
- Abre un archivo .pcap o .pcapng
- Haz clic en "Analizar"
- Espera a que termine
- Haz clic en "Abrir Reporte" para ver los detalles

Cualquier duda:
- Lee QUICK_START.md (instrucciones rápidas)
- Lee INSTALL.md (guía completa)
- Lee README.md (características detalladas)

¡Que disfrutes! 🔍

---
```

---

## 🔄 Opción: Repositorio Git

Si prefieres compartir por Git:

```bash
# En tu repo
git add pcap_analyzer.py README.md requirements.txt ...
git commit -m "Add PCAP Analyzer v1.0"
git push

# Otro usuario
git clone <tu-repo>
cd pcap-analyzer
./setup.sh  # o setup.bat en Windows
```

---

## 🚀 Distribución Profesional (Futuro)

Opciones avanzadas para después:
- Crear ejecutable con PyInstaller (no necesita Python)
- Crear instalador MSI para Windows
- Crear paquete DMG para macOS
- Subir a PyPI como paquete pip

---

## 📝 Notas Importantes

1. **Python DEBE estar instalado** en la otra PC (required)
   - Windows: https://www.python.org/downloads/
   - macOS: `brew install python3`
   - Linux: Generalmente pre-instalado

2. **Los scripts automáticos**:
   - Crean venv automáticamente
   - Instalan scapy automáticamente
   - Verifican que todo funciona

3. **Sin script automático**:
   - El usuario debe seguir INSTALL.md manualmente
   - Más lento pero completamente documentado

---

## ✅ Resumen

| Cuando... | Haz Esto |
|-----------|----------|
| Preparar para distribuir | Sigue "Paso a Paso: Preparar para Distribuir" arriba |
| Enviar por email | ZIP con archivos obligatorios + scripts |
| Dar instrucciones | Envía QUICK_START.md o INSTALL.md |
| Verificar instalación | `python verify_environment.py` |
| Solucionar problemas | Consulta INSTALL.md sección "Solución de Problemas" |

---

**¡Tu aplicación está lista para distribuir! 🎉**
