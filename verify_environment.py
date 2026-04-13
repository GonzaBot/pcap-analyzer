#!/usr/bin/env python3
"""
🔍 PCAP Analyzer - Herramienta de Verificación de Ambiente
Verifica que todas las dependencias están correctamente instaladas.
"""

import sys
import os
from pathlib import Path

# Colores para terminal (Windows 10+ soporta ANSI)
class Colors:
    GREEN = '\033[92m'    # ✓
    RED = '\033[91m'      # ✗
    YELLOW = '\033[93m'   # ⚠
    BLUE = '\033[94m'     # ℹ
    END = '\033[0m'

def print_success(msg):
    print(f"{Colors.GREEN}✓ {msg}{Colors.END}")

def print_error(msg):
    print(f"{Colors.RED}✗ {msg}{Colors.END}")

def print_warning(msg):
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.END}")

def print_info(msg):
    print(f"{Colors.BLUE}ℹ {msg}{Colors.END}")

def check_python_version():
    """Verifica que Python 3.10+ está instalado"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        print_error(f"Python 3.10+ requerido (tienes {version.major}.{version.minor})")
        return False
    print_success(f"Python {version.major}.{version.minor}.{version.micro}")
    return True

def check_tkinter():
    """Verifica que Tkinter está disponible"""
    try:
        import tkinter
        print_success(f"Tkinter disponible")
        return True
    except ImportError:
        print_error("Tkinter no encontrado")
        print_warning("  Windows: Reinstala Python con 'tcl/tk and IDLE' marcado")
        print_warning("  macOS: brew install python-tk")
        print_warning("  Linux: sudo apt install python3-tk")
        return False

def check_scapy():
    """Verifica que Scapy está instalado"""
    try:
        import scapy
        version = scapy.__version__
        print_success(f"Scapy {version}")
        
        # Advertencia si la versión no es la recomendada
        if version != "2.7.0":
            print_warning(f"  Versión recomendada: 2.7.0 (tienes {version})")
        
        return True
    except ImportError:
        print_error("Scapy no encontrado")
        print_warning("  Ejecuta: pip install scapy==2.7.0")
        return False

def check_pcap_file():
    """Verifica que el archivo principal está presente"""
    if os.path.exists("pcap_analyzer.py"):
        size = os.path.getsize("pcap_analyzer.py")
        print_success(f"pcap_analyzer.py encontrado ({size:,} bytes)")
        return True
    else:
        print_error("pcap_analyzer.py no encontrado en directorio actual")
        return False

def check_venv():
    """Verifica si está dentro de un virtual environment"""
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print_success("Virtual environment activado")
        return True
    else:
        print_warning("No estás dentro de un virtual environment")
        print_warning("  Recomendado activar venv para evitar conflictos")
        return False

def check_required_modules():
    """Verifica módulos estándar requeridos"""
    modules = ['threading', 'tkinter', 'collections', 'statistics', 'math']
    all_good = True
    
    for module in modules:
        try:
            __import__(module)
        except ImportError:
            print_error(f"{module} no disponible")
            all_good = False
    
    if all_good:
        print_success(f"Módulos estándar: OK ({len(modules)} verificados)")
    return all_good

def main():
    """Ejecuta todas las verificaciones"""
    print("\n" + "="*60)
    print("🔍 PCAP Analyzer - Verificador de Ambiente")
    print("="*60 + "\n")
    
    print(f"📍 Directorio de trabajo: {os.getcwd()}")
    print(f"🐍 Ejecutable: {sys.executable}\n")
    
    checks = [
        ("Python 3.10+", check_python_version),
        ("Tkinter (GUI)", check_tkinter),
        ("Scapy (Análisis)", check_scapy),
        ("Módulos Estándar", check_required_modules),
        ("PCAP Analyzer", check_pcap_file),
        ("Virtual Environment", check_venv),
    ]
    
    results = []
    for name, check_func in checks:
        print(f"Verificando {name}...")
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print_error(f"Error al verificar {name}: {str(e)}")
            results.append((name, False))
        print()
    
    # Resumen
    print("="*60)
    print("📊 RESUMEN DE VERIFICACIÓN")
    print("="*60 + "\n")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ OK" if result else "✗ FALLIDO"
        color = Colors.GREEN if result else Colors.RED
        print(f"{color}{status:8}{Colors.END} - {name}")
    
    print(f"\n{Colors.BLUE}Resultado: {passed}/{total} verificaciones pasadas{Colors.END}\n")
    
    # Estado final
    if passed == total:
        print_success("¡Todo listo! Puedes ejecutar: python pcap_analyzer.py")
        return 0
    else:
        print_error("Hay problemas. Revisa las advertencias arriba.")
        print_info("Consulta INSTALL.md para más ayuda")
        return 1

if __name__ == "__main__":
    sys.exit(main())
