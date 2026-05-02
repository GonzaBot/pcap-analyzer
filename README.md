# ◈ PCAP Analyzer: Network Forensics Tool 🕵️‍♂️🛡️

**PCAP Analyzer** es una solución avanzada de análisis forense de red desarrollada en Python. Su objetivo es transformar capturas de tráfico crudas en inteligencia accionable, permitiendo a analistas de seguridad y estudiantes de ciberseguridad identificar amenazas, exfiltración de datos y anomalías de red a través de una interfaz gráfica intuitiva y reportes detallados.

---

## 📋 Requisitos de Captura

Para que la herramienta realice un análisis efectivo, necesitas un archivo de tráfico de red en formato `.pcap` o `.pcapng`. Estos archivos pueden generarse mediante:

* **Wireshark:** La herramienta estándar de la industria. Captura el tráfico de tu interfaz y utiliza `Archivo > Guardar como...` para generar el archivo.
* **tcpdump:** Ideal para entornos de servidor o terminal. Usa el comando `tcpdump -i [interfaz] -w captura.pcap`.
* **Tshark:** La versión de línea de comandos de Wireshark.

---

## 🛠️ Instalación y Configuración

Sigue las instrucciones según tu sistema operativo para preparar el entorno.

### 🐧 En Linux (Ubuntu, Kali, Debian)

Abre una terminal y ejecuta los siguientes comandos:

1.  **Clonar el repositorio:**
    ```bash
    git clone [https://github.com/GonzaBot/pcap-analyzer.git](https://github.com/GonzaBot/pcap-analyzer.git)
    ```
2.  **Entrar al directorio:**
    ```bash
    cd pcap-analyzer
    ```
3.  **Configurar dependencias:**
    Otorga permisos de ejecución al script de configuración y ejecútalo:
    ```bash
    chmod +x setup.sh
    ./setup.sh
    ```
4.  **Permisos del programa:**
    Dale permisos de ejecución al archivo principal:
    ```bash
    chmod +x pcap_analyzer.py
    sudo python3 pcap_analyzer.py
    ```

### 🪟 En Windows

1.  Descarga el repositorio o clónalo con Git.
2.  Entra en la carpeta del proyecto.
3.  Ejecuta el archivo **`setup.bat`** haciendo doble clic. Este script se encargará de instalar las librerías necesarias (Scapy) mediante `pip`.

---

## 🚀 Modo de Uso

Una vez instalado, el flujo de trabajo es extremadamente sencillo:

1.  **Ejecución:** Haz **doble clic** directamente en el archivo `pcap_analyzer.py`.
2.  **Carga:** En la interfaz, presiona el botón **"Explorar"** y selecciona tu archivo de captura (`.pcap`).
3.  **Análisis:** Haz clic en **"Analizar"**. El motor procesará cada paquete buscando patrones de ataque.
4.  **Resultados:** Al finalizar, se generará automáticamente un **Reporte Interactivo HTML** en tu carpeta de descargas. Puedes visualizar un resumen de los hallazgos directamente en la pestaña de la aplicación.

---

## 🧠 Inteligencia de Análisis: Patrones Detectados

El motor de **PCAP Analyzer** utiliza heurística y análisis estadístico para detectar los siguientes vectores de ataque:

* **DNS Tunneling:** Identifica consultas DNS con labels largos, alta entropía y señales de payload codificado, agrupadas por dominio base para reducir falsos positivos con CDN, telemetría y servicios legítimos.
* **Beaconing (C2):** Detecta comunicaciones periódicas y constantes entre una IP interna y una externa, patrón clásico utilizado por el malware para recibir instrucciones de servidores remotos.
* **Escaneo de Puertos (Port Scanning):** Alerta cuando un solo host intenta conectarse a una cantidad inusual de puertos en un corto periodo de tiempo (táctica de reconocimiento).
* **SYN Flood (DoS):** Identifica ráfagas de paquetes TCP SYN sin el correspondiente flujo de finalización, técnica utilizada para agotar los recursos de un servidor.
* **ARP Spoofing:** Detecta inconsistencias en las tablas ARP, alertando si una dirección IP está siendo reclamada por múltiples direcciones MAC (Ataque Man-in-the-Middle).
* **Exfiltración de Datos:** Resalta flujos de tráfico sospechosamente grandes hacia IPs externas que podrían indicar el robo de información sensible.
* **Algoritmos DGA:** Identifica patrones de consultas DNS fallidas masivas, comunes en malware que busca dominios generados dinámicamente para evadir listas negras.
* **Retransmisiones Anómalas:** Analiza la salud del tráfico TCP buscando paquetes duplicados que puedan indicar interceptación o problemas críticos de red.
* **ICMP Flood:** Detecta inundaciones de paquetes de "ping" utilizados para denegación de servicio o descubrimiento agresivo de hosts.

---

## ⚖️ Descargo de Responsabilidad (Disclaimer)

Este software ha sido desarrollado exclusivamente con fines **educativos, académicos y de auditoría ética**. El uso de esta herramienta para interceptar o analizar tráfico en redes sin la autorización explícita de los propietarios es ilegal. El autor no se hace responsable por el mal uso que se le pueda dar a este código o a la información obtenida a través de él. **Úsala siempre dentro de la legalidad y la ética profesional.**

---
*Creado con pasión por [GonzaBot](https://github.com/GonzaBot)*
