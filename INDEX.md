<!-- GFM: GitHub Flavored Markdown Header -->
# 🚀 PCAP Analyzer - Documentación Completa

> **Herramienta Profesional de Análisis Forense de Tráfico de Red**

---

## 📖 Índice de Documentación

### 👤 **Para Nuevos Usuarios**
1. **[INSTALL.md](INSTALL.md)** ← **¡COMIENZA AQUÍ!**
   - Instalación rápida automática (Recomendado)
   - Instalación manual paso a paso
   - Solución de problemas
   - Checklist de verificación

2. **[README.md](README.md)**
   - Descripción general del proyecto
   - Características principales
   - Cómo usar la aplicación
   - Conceptos de seguridad
   - Preguntas frecuentes

### 🔧 **Para Desarrolladores**
3. **[DESARROLLO.md](DESARROLLO.md)** *(Próximamente)*
   - Estructura del código
   - Funciones principales
   - Cómo agregar nuevas detecciones
   - Guía de contribución

### 📚 **Recursos Adicionales**
- **requirements.txt** - Dependencias exactas
- **setup.bat** - Instalación automática (Windows)
- **setup.sh** - Instalación automática (macOS/Linux)

---

## 🎯 Guía Rápida por Objetivo

### "¿Quiero instalar en otra PC?"
→ Ve a [INSTALL.md](INSTALL.md) y sigue **Opción 1: Instalación Rápida Automática**

### "¿Cómo uso la aplicación?"
→ Lee [README.md](README.md) sección **"¿Cómo Usar?"**

### "¿Qué detecta exactamente?"
→ Lee [README.md](README.md) sección **"Conceptos de Seguridad"**

### "Tengo un error"
→ Intenta [INSTALL.md](INSTALL.md) sección **"Solución de Problemas"**

### "Quiero modificar el código"
→ Espera por [DESARROLLO.md](DESARROLLO.md)*(Próximamente)*

---

## 📋 Requisitos Mínimos

| Componente | Versión Mínima |
|-----------|----------------|
| **Python** | 3.10 o superior |
| **Scapy** | 2.7.0 |
| **Tkinter** | Incluido con Python |
| **OS** | Windows, macOS, o Linux |

---

## 🚀 Inicio Rápido

### En 3 Pasos

**Paso 1:** Descargar
```bash
git clone <url-del-repo>
cd pcap-analyzer
```

**Paso 2:** Ejecutar script (Windows o macOS/Linux)
```bash
# Windows
setup.bat

# macOS/Linux
chmod +x setup.sh
./setup.sh
```

**Paso 3:** Abrir un PCAP
- Ejecutar la aplicación
- Hacer clic en "Explorar"
- Seleccionar archivo `.pcap` o `.pcapng`
- Hacer clic en "Analizar"

---

## 📊 Detecciones Disponibles

La herramienta detecta automáticamente:

1. **DNS Tunneling** - Exfiltración de datos a través de DNS
2. **Beaconing/C2** - Comunicaciones C2 periódicas sospechosas
3. **Port Scanning** - Escaneos automatizados de puertos
4. **SYN Flooding** - Ataques DoS con paquetes SYN
5. **ARP Spoofing** - Suplantación de identidad en la red
6. **TCP Retransmissions** - Retransmisiones exesivas
7. **Data Exfiltration** - Transferencias sospechosas de datos
8. **DGA/DNS Masivo** - Resoluciones de dominio generadas algorítmicamente
9. **ICMP Flooding** - Ataques DoS con ICMP

---

## 🎓 Aprende Haciendo

### Ejemplo 1: Tu Primer Análisis
1. Abre PCAP Analyzer
2. Selecciona un archivo PCAP
3. Haz clic en "Analizar"
4. Espera mientras aparece la barra de progreso
5. Haz clic en "Abrir Reporte HTML"
6. ¡Explora los descubrimientos!

### Ejemplo 2: Buscar Activity Específica
En la pestaña "Findings", puedes:
- Ver un resumen ejecutivo
- Explorar cada amenaza detectada
- Ver detalles de conexiones sospechosas
- Exportar el reporte HTML

---

## 🛡️ Características Principales

✨ **Interfaz Intuitiva en Dark Mode**
- Tema cybersecurity oscuro
- Navegación por pestañas
- Progreso en tiempo real

📊 **Análisis Avanzado**
- 9 tipos de detecciones
- Cálculos estadísticos (entropía, desviación estándar)
- Correlación de eventos

🔍 **Salida Detallada**
- Consola en vivo
- Tabla de conexiones principales
- Reporte HTML profesional
- Detalles por puerto

📈 **Reportes HTML**
- Visualización profesional
- Tablas interactivas
- Recomendaciones de acción

---

## 📁 Archivos del Proyecto

```
pcap-analyzer/
│
├── 📄 pcap_analyzer.py      Aplicación principal (~1050 líneas)
├── 📖 README.md             Documentación completa
├── 📋 INSTALL.md            Guía de instalación
├── 📑 INDEX.md              Este archivo
│
├── ⚙️ requirements.txt       Dependencias exactas
├── 🔧 setup.bat             Instalación Windows
├── 🔧 setup.sh              Instalación macOS/Linux
└── 🚫 .gitignore            Archivos a ignorar
```

---

## 💡 Consejos Útiles

### Recolectar Tráfico de Red
```bash
# Windows (como administrador)
# Dentro de la GUI, selecciona tu interfaz

# Linux/macOS
sudo tcpdump -i eth0 -w captura.pcap

# O usa Wireshark (GUI) en cualquier SO
```

### Analizar Archivos Grandes
- PCAP Analyzer puede procesar archivos de varios GB
- Para archivos >2GB, puede tardar varios minutos
- La barra de progreso indicará el avance

### Interpretar Resultados
- Lee la sección "Descripción de Amenazas" en README.md
- Cada detección incluye confianza y detalles
- Revisa el reporte HTML para contexto completo

---

## ❓ Preguntas Frecuentes

**P: ¿Funciona en todas las plataformas?**
R: Sí, Windows, macOS y Linux son soportados.

**P: ¿Necesito permisos de administrador?**
R: Para capturar tráfico en vivo: sí. Para analizar archivos PCAP: no.

**P: ¿Es de código abierto?**
R: Sí, consulta el README.md para más detalles.

**P: ¿Cuántos archivos PCAP puedo analizar?**
R: Ilimitados, pero archivos muy grandes pueden tardar.

---

## 🆘 Obtener Ayuda

1. **Para Instalación:** Lee [INSTALL.md](INSTALL.md)
2. **Para Uso:** Lee [README.md](README.md)
3. **Para Errores:** Busca en [INSTALL.md](INSTALL.md) Solución de Problemas
4. **Para Código:** Espera por [DESARROLLO.md](DESARROLLO.md)

---

## 📞 Contacto & Soporte

- 📧 Email: contact@domain.com *(Próximamente)*
- 🐛 Reportar bugs: GitHub Issues *(Próximamente)*
- 💬 Discusiones: GitHub Discussions *(Próximamente)*

---

## 📜 Términos Legales

⚠️ **DESCARGO DE RESPONSABILIDAD:**
- Esta herramienta es educativa
- Úsala solo en redes que controles o autorices
- Asume responsabilidad por tu uso
- Cumple con leyes locales

Consulta [README.md](README.md) para más detalles.

---

## 🎯 Tu Próximo Paso

👉 **[Ir a INSTALL.md →](INSTALL.md)**

---

**Última actualización:** 2024
**Versión:** 1.0
**Estado:** Production-Ready ✅
