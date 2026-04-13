@echo off
REM ============================================================================
REM PCAP Analyzer - Quick Setup Script (Windows)
REM ============================================================================
REM Este script automatiza la instalación en una PC nueva

echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║     PCAP Analyzer - Instalacion Automatica (Windows)          ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.

REM Verificar si Python está instalado
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python no esta instalado o no esta en PATH
    echo.
    echo Descarga Python desde: https://www.python.org/downloads/
    echo Asegurate de marcar "Add Python to PATH" durante la instalacion
    pause
    exit /b 1
)

echo [✓] Python detectado
python --version
echo.

REM Crear entorno virtual
echo [*] Creando entorno virtual (.venv)...
python -m venv .venv
if errorlevel 1 (
    echo [ERROR] Fallo al crear el entorno virtual
    pause
    exit /b 1
)
echo [✓] Entorno virtual creado
echo.

REM Activar entorno virtual
echo [*] Activando entorno virtual...
call .\.venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Fallo al activar el entorno virtual
    pause
    exit /b 1
)
echo [✓] Entorno virtual activado
echo.

REM Instalar dependencias
echo [*] Instalando dependencias (scapy)...
python -m pip install --upgrade pip
if errorlevel 1 (
    echo [ERROR] Fallo al actualizar pip
    pause
    exit /b 1
)
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Fallo al instalar dependencias
    echo.
    echo Intenta manualmente:
    echo   python -m pip install -r requirements.txt
    pause
    exit /b 1
)
echo [✓] Dependencias instaladas
echo.

REM Verificar instalacion
echo [*] Verificando instalacion...
python -c "from scapy import __version__; print('[✓] Scapy ' + __version__ + ' funcionando correctamente')"
if errorlevel 1 (
    echo [ERROR] Fallo la verificacion de scapy
    echo.
    echo Intenta manualmente:
    echo   python -c "import scapy; print(scapy.__version__)"
    pause
    exit /b 1
)
echo.

REM Listo
echo ╔════════════════════════════════════════════════════════════════╗
echo ║  [✓] INSTALACION COMPLETADA EXITOSAMENTE                      ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.
echo El entorno virtual esta ACTIVADO en esta terminal.
echo.
echo Puedes ejecutar ahora:
echo   python pcap_analyzer.py
echo.
echo En futuras sesiones, ejecuta:
echo   .venv\Scripts\activate.bat
echo   python pcap_analyzer.py
echo.
echo Presiona cualquier tecla para abrir la aplicacion automaticamente...
pause
echo.
echo [*] Iniciando aplicacion...
python pcap_analyzer.py
if errorlevel 1 (
    echo [ERROR] Fallo al iniciar la aplicacion
    pause
)
