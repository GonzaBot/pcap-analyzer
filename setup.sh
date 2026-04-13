#!/bin/bash

# ============================================================================
# PCAP Analyzer - Quick Setup Script (macOS/Linux)
# ============================================================================
# Este script automatiza la instalación en una PC nueva

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     PCAP Analyzer - Instalacion Automatica (macOS/Linux)      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Verificar si Python está instalado
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 no está instalado"
    echo ""
    echo "En macOS, instala con:"
    echo "  brew install python3"
    echo ""
    echo "En Linux (Debian/Ubuntu), instala con:"
    echo "  sudo apt install python3 python3-pip python3-venv"
    echo ""
    exit 1
fi

echo "[✓] Python detectado"
python3 --version
echo ""

# Instalar dependencias del sistema para scapy en Linux
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "[*] Detectado Linux. Instalando dependencias del sistema para Scapy..."
    
    # Detectar si es Debian/Ubuntu
    if command -v apt &> /dev/null; then
        echo "[*] Instalando libpcap (requerido para Scapy)..."
        sudo apt update > /dev/null 2>&1
        sudo apt install -y libpcap-dev > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "[WARNING] No se pudieron instalar las dependencias del sistema automáticamente."
            echo "Intenta manualmente:"
            echo "  sudo apt install libpcap-dev"
            echo ""
        else
            echo "[✓] Dependencias del sistema instaladas"
        fi
    # Detectar si es Red Hat/CentOS/Fedora
    elif command -v dnf &> /dev/null; then
        echo "[*] Instalando libpcap (requerido para Scapy)..."
        sudo dnf install -y libpcap-devel > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "[WARNING] No se pudieron instalar las dependencias del sistema automáticamente."
            echo "Intenta manualmente:"
            echo "  sudo dnf install libpcap-devel"
            echo ""
        else
            echo "[✓] Dependencias del sistema instaladas"
        fi
    fi
    echo ""
fi

# Crear entorno virtual
echo "[*] Creando entorno virtual (.venv)..."
python3 -m venv .venv
if [ $? -ne 0 ]; then
    echo "[ERROR] Fallo al crear el entorno virtual"
    exit 1
fi
echo "[✓] Entorno virtual creado"
echo ""

# Activar entorno virtual
echo "[*] Activando entorno virtual..."
source .venv/bin/activate
if [ $? -ne 0 ]; then
    echo "[ERROR] Fallo al activar el entorno virtual"
    exit 1
fi
echo "[✓] Entorno virtual activado"
echo ""

# Instalar dependencias Python
echo "[*] Instalando dependencias Python (scapy)..."
python3 -m pip install --upgrade pip
if [ $? -ne 0 ]; then
    echo "[ERROR] Fallo al actualizar pip"
    exit 1
fi
python3 -m pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[ERROR] Fallo al instalar dependencias"
    echo ""
    echo "Intenta manualmente:"
    echo "  python3 -m pip install -r requirements.txt"
    exit 1
fi
echo "[✓] Dependencias Python instaladas"
echo ""

# Verificar instalacion
echo "[*] Verificando instalación..."
python3 -c "from scapy import __version__; print('[✓] Scapy ' + __version__ + ' funcionando correctamente')"
if [ $? -ne 0 ]; then
    echo "[ERROR] Falló la verificación de scapy"
    echo ""
    echo "Intenta manualmente:"
    echo "  python3 -c \"import scapy; print(scapy.__version__)\""
    exit 1
fi
echo ""

# Listo
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  [✓] INSTALACION COMPLETADA EXITOSAMENTE                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "El entorno virtual está ACTIVADO en esta terminal."
echo ""
echo "Puedes ejecutar ahora:"
echo "  python3 pcap_analyzer.py"
echo ""
echo "En futuras sesiones, ejecuta:"
echo "  source .venv/bin/activate"
echo "  python3 pcap_analyzer.py"
echo ""
echo "Presiona ENTER para abrir la aplicación automáticamente..."
read
echo ""
echo "[*] Iniciando aplicación..."
python3 pcap_analyzer.py
