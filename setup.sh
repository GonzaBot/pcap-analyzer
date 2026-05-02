#!/bin/bash

# ============================================================================
# PCAP Analyzer - Quick Setup Script (macOS/Linux)
# ============================================================================

set -euo pipefail  # Salir ante errores, variables sin definir, y pipes fallidos

# ── Colores para output ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "    [*] $*"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── 1. Verificar Python 3 ────────────────────────────────────────────────────
echo ""
info "Verificando Python 3..."

if ! command -v python3 &>/dev/null; then
    err "Python 3 no está instalado."
    echo ""
    echo "  macOS  → brew install python3"
    echo "  Ubuntu → sudo apt install python3 python3-pip python3-venv"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1)
ok "Python detectado: $PYTHON_VERSION"
echo ""

# ── 2. Dependencias del sistema (solo Linux) ─────────────────────────────────
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    info "Sistema Linux detectado. Verificando libpcap..."

    install_pkg() {
        local pkg_manager="$1"
        local pkg="$2"
        local install_cmd="$3"

        if command -v "$pkg_manager" &>/dev/null; then
            info "Instalando $pkg con $pkg_manager..."
            if sudo -n true 2>/dev/null; then
                eval "$install_cmd" > /dev/null 2>&1 && ok "$pkg instalado." || \
                    warn "No se pudo instalar $pkg. Ejecutá manualmente: $install_cmd"
            else
                warn "Se necesitan permisos de sudo para instalar $pkg."
                echo "  Ejecutá manualmente: $install_cmd"
            fi
            return 0
        fi
        return 1
    }

    install_pkg "apt" "libpcap-dev" \
        "sudo apt-get update -qq && sudo apt-get install -y libpcap-dev" || \
    install_pkg "dnf" "libpcap-devel" \
        "sudo dnf install -y libpcap-devel" || \
    install_pkg "yum" "libpcap-devel" \
        "sudo yum install -y libpcap-devel" || \
        warn "Gestor de paquetes no reconocido. Instalá libpcap manualmente."
    echo ""
fi

# ── 3. Crear entorno virtual ─────────────────────────────────────────────────
VENV_DIR=".venv"

info "Creando entorno virtual en $VENV_DIR/..."

if python3 -m venv "$VENV_DIR"; then
    ok "Entorno virtual creado."
else
    err "Fallo al crear el entorno virtual."
    echo "  Verificá que el módulo venv esté disponible:"
    echo "  sudo apt install python3-venv  (Ubuntu/Debian)"
    exit 1
fi
echo ""

# ── 4. Activar entorno virtual ───────────────────────────────────────────────
ACTIVATE_SCRIPT="$VENV_DIR/bin/activate"

if [[ ! -f "$ACTIVATE_SCRIPT" ]]; then
    err "No se encontró el script de activación: $ACTIVATE_SCRIPT"
    exit 1
fi

# shellcheck source=/dev/null
source "$ACTIVATE_SCRIPT"
ok "Entorno virtual activado."
echo ""

# ── 5. Actualizar pip ────────────────────────────────────────────────────────
info "Actualizando pip..."
if python3 -m pip install --upgrade pip --quiet; then
    ok "pip actualizado."
else
    warn "No se pudo actualizar pip. Continuando de todas formas..."
fi
echo ""

# ── 6. Instalar dependencias Python ─────────────────────────────────────────
REQUIREMENTS_FILE="requirements.txt"

if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
    warn "No se encontró $REQUIREMENTS_FILE. Instalando solo scapy..."
    INSTALL_CMD="python3 -m pip install scapy --quiet"
else
    info "Instalando desde $REQUIREMENTS_FILE..."
    INSTALL_CMD="python3 -m pip install -r $REQUIREMENTS_FILE --quiet"
fi

if eval "$INSTALL_CMD"; then
    ok "Dependencias Python instaladas."
else
    err "Fallo al instalar dependencias."
    echo ""
    echo "  Intentá manualmente:"
    echo "    source $VENV_DIR/bin/activate"
    [[ -f "$REQUIREMENTS_FILE" ]] && \
        echo "    python3 -m pip install -r $REQUIREMENTS_FILE" || \
        echo "    python3 -m pip install scapy"
    exit 1
fi
echo ""

# ── 7. Verificar que Scapy funcione correctamente ────────────────────────────
info "Verificando instalación de Scapy..."

SCAPY_VERSION=$(python3 -c "import scapy; print(scapy.__version__)" 2>/dev/null || true)

if [[ -z "$SCAPY_VERSION" ]]; then
    err "Scapy no está disponible o no pudo importarse."
    echo ""
    echo "  Intentá manualmente dentro del entorno virtual:"
    echo "    source $VENV_DIR/bin/activate"
    echo "    python3 -c \"import scapy; print(scapy.__version__)\""
    exit 1
fi

ok "Scapy $SCAPY_VERSION funcionando correctamente."
echo ""

# ── 8. Listo ──────────────────────────────────────────────────────────────────
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  ✓  INSTALACIÓN COMPLETADA EXITOSAMENTE                       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "El entorno virtual está ACTIVADO en esta terminal."
echo ""
echo "  Ejecutar ahora:          python3 pcap_analyzer.py"
echo "  En futuras sesiones:"
echo "    source $VENV_DIR/bin/activate"
echo "    python3 pcap_analyzer.py"
echo ""
read -rp "Presioná ENTER para iniciar la aplicación..."
echo ""
info "Iniciando aplicación..."
python3 pcap_analyzer.py
