#!/usr/bin/env python3
"""
PCAP Analyzer — Herramienta de Análisis Forense de Red
Requiere: pip install scapy
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import math
import statistics
import webbrowser
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

try:
    from scapy.all import rdpcap, DNS, DNSQR, TCP, IP, ARP, UDP, Raw, Ether
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ─── Paleta de colores ────────────────────────────────────────────────────────
C = {
    "bg":     "#080c10",
    "bg2":    "#0e1318",
    "bg3":    "#141b22",
    "bg4":    "#1c2530",
    "accent": "#00d4ff",
    "green":  "#00ff88",
    "yellow": "#ffd93d",
    "red":    "#ff4757",
    "orange": "#ff6b35",
    "purple": "#bd93f9",
    "text":   "#e2e8f0",
    "muted":  "#64748b",
    "border": "#1e293b",
    "glow":   "#00d4ff",
}

RISK_COLORS = {
    "CRITICAL": "#ff4757",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffd93d",
    "LOW":      "#00ff88",
    "INFO":     "#00d4ff",
}

# ─── Motor de análisis ────────────────────────────────────────────────────────

def darken_hex(hex_color: str, factor: float) -> str:
    """Oscurece un color hexadecimal. factor: 0.5 = 50% más oscuro"""
    hex_color = hex_color.lstrip('#')
    r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
    r, g, b = int(r * factor), int(g * factor), int(b * factor)
    return f"#{r:02x}{g:02x}{b:02x}"

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = Counter(data.lower())
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def analyze_pcap(filepath: str, progress_callback=None) -> dict:
    findings = {
        "metadata": {},
        "findings": [],
        "statistics": {},
        "top_ips": [],
    }

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        raise RuntimeError(f"No se pudo leer el archivo: {e}")

    total = len(packets)
    if total == 0:
        raise RuntimeError("El archivo no contiene paquetes.")

    findings["metadata"] = {
        "file": os.path.basename(filepath),
        "total_packets": total,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Estructuras de datos
    dns_queries         = []
    dns_by_domain       = defaultdict(int)
    ip_pair_times       = defaultdict(list)
    ip_pair_bytes       = defaultdict(int)
    port_targets        = defaultdict(set)
    port_details        = defaultdict(lambda: defaultdict(int))  # (src_ip, dst_ip, sport, dport) -> count
    syn_counts          = defaultdict(int)
    synack_counts       = defaultdict(int)
    arp_ip_mac          = defaultdict(set)
    tcp_seq_seen        = defaultdict(int)
    tcp_retrans_detail  = defaultdict(int)  # (src_ip, dst_ip, sport, dport) -> retrans count
    retransmissions     = 0
    ip_total_bytes      = defaultdict(int)
    ip_packet_count     = defaultdict(int)
    icmp_counts         = defaultdict(int)
    udp_sizes           = defaultdict(list)
    tcp_flags_seen      = defaultdict(int)  # Track different flag combinations
    connection_list     = []  # (src_ip, dst_ip, sport, dport, protocol, packet_count, total_bytes)

    for i, pkt in enumerate(packets):
        if progress_callback and i % 300 == 0:
            progress_callback(int(i / total * 72))

        pkt_len  = len(pkt)
        pkt_time = float(pkt.time)

        # ARP spoofing
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            if arp.op == 2:  # ARP reply
                arp_ip_mac[arp.psrc].add(arp.hwsrc)

        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        ip_total_bytes[src_ip]   += pkt_len
        ip_packet_count[src_ip]  += 1
        ip_pair_bytes[(src_ip, dst_ip)] += pkt_len
        ip_pair_times[(src_ip, dst_ip)].append(pkt_time)

        # DNS
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                dns_queries.append((qname, pkt_time))
                parts = qname.split(".")
                base  = ".".join(parts[-2:]) if len(parts) >= 2 else qname
                dns_by_domain[base] += 1
            except Exception:
                pass

        # UDP sizes (para DNS tunneling por tamaño)
        if pkt.haslayer(UDP):
            udp_sizes[(src_ip, dst_ip)].append(pkt_len)

        # TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            port_targets[src_ip].add(tcp.dport)
            
            # Track port-level connections
            conn_key = (src_ip, dst_ip, tcp.sport, tcp.dport)
            port_details[conn_key]["count"] += 1
            port_details[conn_key]["bytes"] += pkt_len
            port_details[conn_key]["protocol"] = "TCP"
            tcp_flags_seen[f"{src_ip}:{tcp.dport}"] += 1

            if flags == 0x02:            # SYN puro
                syn_counts[src_ip] += 1
            if flags == 0x12:            # SYN-ACK
                synack_counts[dst_ip] += 1

            # Retransmisiones reales (mismo (src,dst,sport,dport,seq))
            key = (src_ip, dst_ip, tcp.sport, tcp.dport, tcp.seq)
            if tcp_seq_seen[key] > 0:
                retransmissions += 1
                tcp_retrans_detail[conn_key] += 1
            tcp_seq_seen[key] += 1

        # ICMP flood
        if pkt.haslayer("ICMP"):
            icmp_counts[src_ip] += 1

    if progress_callback:
        progress_callback(76)

    # ─── Detección 1: DNS Tunneling ──────────────────────────────────────────
    suspicious_dns = []
    for qname, ts in dns_queries:
        subdomain = qname.split(".")[0] if "." in qname else qname
        entropy   = shannon_entropy(subdomain)
        if len(qname) > 52 or entropy > 3.6:
            suspicious_dns.append((qname, entropy))

    if suspicious_dns:
        examples = "\n".join(
            f"  • {q[:80]}  (entropía: {e:.2f})"
            for q, e in suspicious_dns[:4]
        )
        findings["findings"].append({
            "id":    "DNS_TUNNELING",
            "title": "Posible DNS Tunneling",
            "risk":  "HIGH",
            "count": len(suspicious_dns),
            "description": (
                f"Se detectaron {len(suspicious_dns)} consultas DNS con dominios inusualmente "
                f"largos o con alta entropía de Shannon (> 3.6 bits)."
            ),
            "cause": (
                "El DNS tunneling abusa del protocolo DNS para ocultar datos dentro de consultas "
                "aparentemente legítimas. El malware codifica datos en el subdominio (ej. Base64 o hex) "
                "para exfiltrar información o comunicarse con servidores C2, ya que el tráfico DNS "
                "raramente es inspeccionado o bloqueado por firewalls corporativos."
            ),
            "examples": examples,
            "recommendation": (
                "Habilitar DNS Security Extensions (DNSSEC). Implementar un DNS sink-hole o resolver "
                "con filtrado (Cisco Umbrella, Pi-hole). Investigar los dominios en VirusTotal o Shodan."
            ),
        })

    # ─── Detección 2: Beaconing / C2 ─────────────────────────────────────────
    beacon_pairs = []
    for (src, dst), times in ip_pair_times.items():
        if len(times) < 12:
            continue
        times_sorted = sorted(times)
        intervals = [times_sorted[j+1] - times_sorted[j] for j in range(len(times_sorted)-1)]
        intervals  = [x for x in intervals if x > 0.1]  # filtrar ruido
        if len(intervals) < 5:
            continue
        try:
            avg = statistics.mean(intervals)
            std = statistics.stdev(intervals)
            cv  = std / avg if avg > 0 else 999
            if cv < 0.18 and 4 <= avg <= 900:
                beacon_pairs.append((src, dst, avg, cv, len(times)))
        except Exception:
            pass

    if beacon_pairs:
        beacon_pairs.sort(key=lambda x: x[3])
        examples = "\n".join(
            f"  • {src} → {dst}  |  cada {avg:.1f}s  |  regularidad {(1-cv)*100:.0f}%  ({cnt} paqts)"
            for src, dst, avg, cv, cnt in beacon_pairs[:4]
        )
        findings["findings"].append({
            "id":    "BEACONING",
            "title": "Beaconing — Comunicación C2 activa",
            "risk":  "CRITICAL",
            "count": len(beacon_pairs),
            "description": (
                f"Se detectaron {len(beacon_pairs)} par(es) IP con comunicación periódica "
                f"extremadamente regular (coeficiente de variación < 18%)."
            ),
            "cause": (
                "El beaconing es la señal más característica de un implante de malware activo. "
                "Los RATs (Remote Access Trojans), botnets, ransomware pre-cifrado y APTs se "
                "'reportan' a su servidor C2 en intervalos fijos para recibir órdenes. "
                "Ningún usuario humano genera este patrón tan mecánico y regular."
            ),
            "examples": examples,
            "recommendation": (
                "Aislar de inmediato los equipos origen de la red. Capturar imagen forense del "
                "disco antes de hacer cualquier cambio. Analizar procesos activos con Autoruns, "
                "Process Monitor y Wireshark local en el equipo afectado."
            ),
        })

    # ─── Detección 3: Port Scan ───────────────────────────────────────────────
    scanners = [(ip, ports) for ip, ports in port_targets.items() if len(ports) > 35]
    scanners.sort(key=lambda x: -len(x[1]))

    if scanners:
        examples = "\n".join(
            f"  • {ip}  →  {len(ports)} puertos distintos escaneados"
            for ip, ports in scanners[:4]
        )
        findings["findings"].append({
            "id":    "PORT_SCAN",
            "title": "Escaneo de Puertos",
            "risk":  "HIGH",
            "count": len(scanners),
            "description": (
                f"{len(scanners)} IP(s) se conectaron a más de 35 puertos distintos, "
                f"patrón clásico de reconocimiento activo."
            ),
            "cause": (
                "El escaneo de puertos es la fase de reconocimiento previo a un ataque. "
                "Indica: exploración de vulnerabilidades con herramientas como Nmap o Masscan, "
                "un gusano buscando propagarse por la red, o un atacante ya dentro de la red "
                "mapeando los servicios disponibles para escalar privilegios o moverse lateralmente."
            ),
            "examples": examples,
            "recommendation": (
                "Si el origen es externo: revisar y endurecer las reglas del firewall perimetral. "
                "Si el origen es interno: el equipo está probablemente comprometido. "
                "Correlacionar con logs de sistemas de detección de intrusos (IDS/IPS)."
            ),
        })

    # ─── Detección 4: SYN Flood ───────────────────────────────────────────────
    syn_flood = []
    for ip, sc in syn_counts.items():
        sack  = synack_counts.get(ip, 0)
        ratio = sc / (sack + 1)
        if sc > 180 and ratio > 12:
            syn_flood.append((ip, sc, ratio))
    syn_flood.sort(key=lambda x: -x[1])

    if syn_flood:
        examples = "\n".join(
            f"  • {ip}  →  {cnt:,} SYN  |  ratio SYN/SYN-ACK: {ratio:.0f}x"
            for ip, cnt, ratio in syn_flood[:4]
        )
        findings["findings"].append({
            "id":    "SYN_FLOOD",
            "title": "SYN Flood — Posible ataque DDoS",
            "risk":  "CRITICAL",
            "count": len(syn_flood),
            "description": (
                f"{len(syn_flood)} IP(s) con alto volumen de paquetes SYN sin completar el "
                f"handshake TCP (sin SYN-ACK correspondiente)."
            ),
            "cause": (
                "Un SYN flood es un ataque de denegación de servicio que agota la tabla de "
                "conexiones semidefinidas del servidor (backlog). Cada SYN abre una conexión "
                "incompleta que espera el ACK final que nunca llega. Con suficiente volumen, "
                "el servidor deja de aceptar conexiones legítimas. También puede ser un escáner "
                "stealth (SYN scan de Nmap) que no completa el handshake intencionalmente."
            ),
            "examples": examples,
            "recommendation": (
                "Activar SYN cookies en el kernel del servidor (net.ipv4.tcp_syncookies=1). "
                "Implementar rate-limiting por IP en el firewall. Considerar protección anti-DDoS "
                "a nivel de proveedor (Cloudflare, AWS Shield)."
            ),
        })

    # ─── Detección 5: ARP Spoofing / MITM ────────────────────────────────────
    arp_spoof = {ip: macs for ip, macs in arp_ip_mac.items() if len(macs) > 1}

    if arp_spoof:
        examples = "\n".join(
            f"  • IP {ip}  →  MACs: {', '.join(sorted(macs))}"
            for ip, macs in list(arp_spoof.items())[:4]
        )
        findings["findings"].append({
            "id":    "ARP_SPOOF",
            "title": "ARP Spoofing — Ataque Man-in-the-Middle",
            "risk":  "CRITICAL",
            "count": len(arp_spoof),
            "description": (
                f"{len(arp_spoof)} IP(s) respondieron ARP con múltiples MACs distintas en la misma sesión."
            ),
            "cause": (
                "ARP Spoofing es la base de la mayoría de ataques MITM en redes LAN. "
                "El atacante responde falsamente a consultas ARP asociando su MAC a la IP de otro "
                "host (gateway, servidor) para interceptar y redirigir el tráfico. "
                "Esto permite: captura de credenciales en texto plano, robo de cookies de sesión, "
                "downgrade de HTTPS, inyección de código malicioso en HTTP, y lateral movement."
            ),
            "examples": examples,
            "recommendation": (
                "Activar Dynamic ARP Inspection (DAI) en switches gestionados. "
                "Configurar entradas ARP estáticas para el gateway. "
                "Implementar 802.1X para control de acceso a la red. "
                "Usar herramientas como XArp para monitoreo continuo de ARP."
            ),
        })

    # ─── Detección 6: Retransmisiones TCP ────────────────────────────────────
    if retransmissions > 60:
        risk = "HIGH" if retransmissions > 250 else "MEDIUM"
        # Detalles de retransmisiones por flujo
        retrans_by_flow = [(src_ip, dst_ip, sport, dport, cnt) 
                          for (src_ip, dst_ip, sport, dport), cnt in tcp_retrans_detail.items() if cnt > 2]
        retrans_by_flow.sort(key=lambda x: -x[4])
        
        examples = "\n".join(
            f"  • {src_ip}:{sport} → {dst_ip}:{dport}  |  {cnt} retransmisiones"
            for src_ip, dst_ip, sport, dport, cnt in retrans_by_flow[:6]
        )
        
        findings["findings"].append({
            "id":    "TCP_RETRANS",
            "title": "Alto número de retransmisiones TCP",
            "risk":  risk,
            "count": retransmissions,
            "description": (
                f"Se detectaron {retransmissions:,} retransmisiones TCP "
                f"(paquetes con número de secuencia duplicado) en {len(retrans_by_flow)} flujos distintos."
            ),
            "cause": (
                "En contexto normal indica congestión o pérdida de paquetes. "
                "En contexto de seguridad puede ser síntoma de: un ataque MITM que altera "
                "o descarta paquetes selectivamente, un IDS/IPS inline con reglas agresivas, "
                "un ataque de desincronización TCP, o degradación de servicio intencional "
                "para frustrar conexiones legítimas."
            ),
            "examples": examples,
            "recommendation": (
                "Verificar la calidad del enlace físico y descartar problemas de hardware. "
                "Si la infraestructura es estable, cruzar con otros hallazgos (especialmente ARP Spoofing). "
                "Revisar logs del IDS/IPS en busca de reglas de drop. Analizar captures con tcpdump en los flujos afectados."
            ),
        })

    # ─── Detección 7: Exfiltración de datos ──────────────────────────────────
    large_flows = [
        (src, dst, b)
        for (src, dst), b in ip_pair_bytes.items()
        if b > 4_500_000
    ]
    large_flows.sort(key=lambda x: -x[2])

    if large_flows:
        examples = "\n".join(
            f"  • {src} → {dst}  |  {b/1024/1024:.1f} MB transferidos"
            for src, dst, b in large_flows[:4]
        )
        findings["findings"].append({
            "id":    "DATA_EXFIL",
            "title": "Transferencias de Datos Inusualmente Grandes",
            "risk":  "HIGH",
            "count": len(large_flows),
            "description": (
                f"{len(large_flows)} flujo(s) con más de 4.5 MB de datos transferidos entre pares IP."
            ),
            "cause": (
                "Transferencias masivas hacia destinos externos o inusuales pueden indicar "
                "exfiltración de datos: bases de datos, archivos confidenciales, backups o "
                "credenciales siendo enviados fuera de la organización. "
                "También puede ser tráfico legítimo (actualizaciones, backup en nube), "
                "pero debe validarse el destino y el proceso responsable."
            ),
            "examples": examples,
            "recommendation": (
                "Identificar el proceso que genera el flujo con netstat o Process Monitor. "
                "Verificar el destino en listas de reputación (VirusTotal, AbuseIPDB). "
                "Implementar DLP (Data Loss Prevention) en el firewall perimetral."
            ),
        })

    # ─── Detección 8: DGA / Consultas DNS excesivas ───────────────────────────
    high_dns = [(d, c) for d, c in dns_by_domain.items() if c > 90]
    high_dns.sort(key=lambda x: -x[1])

    if high_dns:
        examples = "\n".join(f"  • {d}  →  {c} consultas" for d, c in high_dns[:4])
        findings["findings"].append({
            "id":    "DGA_DNS",
            "title": "Consultas DNS Masivas — Posible DGA",
            "risk":  "MEDIUM",
            "count": len(high_dns),
            "description": (
                f"{len(high_dns)} dominio(s) con más de 90 consultas DNS en la captura."
            ),
            "cause": (
                "Un Domain Generation Algorithm (DGA) genera automáticamente cientos de dominios "
                "pseudoaleatorios. El malware los prueba uno a uno hasta encontrar el que su operador "
                "ha registrado recientemente. Este mecanismo hace muy difícil bloquear el C2 "
                "por dominio fijo. Es usado por familias como Conficker, Emotet, Dridex y TrickBot."
            ),
            "examples": examples,
            "recommendation": (
                "Analizar los dominios consultados en VirusTotal, passivedns.com o similar. "
                "Monitorear cuáles resuelven exitosamente y correlacionar con tráfico posterior. "
                "Implementar filtrado DNS con feeds de threat intelligence (Quad9, Umbrella)."
            ),
        })

    # ─── Detección 9: ICMP Flood ──────────────────────────────────────────────
    icmp_flood = [(ip, cnt) for ip, cnt in icmp_counts.items() if cnt > 300]
    icmp_flood.sort(key=lambda x: -x[1])

    if icmp_flood:
        examples = "\n".join(f"  • {ip}  →  {cnt:,} paquetes ICMP" for ip, cnt in icmp_flood[:4])
        findings["findings"].append({
            "id":    "ICMP_FLOOD",
            "title": "ICMP Flood — Posible Ping Flood / Smurf",
            "risk":  "MEDIUM",
            "count": len(icmp_flood),
            "description": (
                f"{len(icmp_flood)} IP(s) generaron más de 300 paquetes ICMP."
            ),
            "cause": (
                "Un ICMP flood o Ping flood es un ataque de denegación de servicio que satura "
                "el ancho de banda y los recursos del destino con paquetes ICMP Echo Request. "
                "El ataque Smurf usa la dirección broadcast para amplificar el tráfico. "
                "También puede indicar un escáner de red (nmap -sn) o diagnóstico masivo."
            ),
            "examples": examples,
            "recommendation": (
                "Limitar el rate de ICMP en el firewall (ej. máximo 10 pps por IP). "
                "Deshabilitar respuesta a ICMP broadcast en routers. "
                "Verificar si el origen es interno (herramienta de diagnóstico) o externo (ataque)."
            ),
        })

    if progress_callback:
        progress_callback(92)

    # Estadísticas generales y conexiones activas
    top_ips_list = sorted(ip_packet_count.items(), key=lambda x: -x[1])[:10]
    
    # Top conexiones TCP por volumen
    conn_by_bytes = sorted(
        [(src_ip, dst_ip, sport, dport, port_details[(src_ip, dst_ip, sport, dport)]["count"], 
          port_details[(src_ip, dst_ip, sport, dport)].get("bytes", 0))
         for (src_ip, dst_ip, sport, dport) in port_details.keys()],
        key=lambda x: -x[5]
    )[:10]
    
    findings["statistics"] = {
        "total_packets":       total,
        "unique_ips":          len(ip_packet_count),
        "dns_queries":         len(dns_queries),
        "tcp_retransmissions": retransmissions,
        "unique_dns_domains":  len(dns_by_domain),
        "tcp_connections":     len(port_details),
    }
    findings["top_ips"] = [
        {"ip": ip, "packets": cnt, "bytes": ip_total_bytes.get(ip, 0)}
        for ip, cnt in top_ips_list
    ]
    
    findings["top_connections"] = [
        {"src": src_ip, "dst": dst_ip, "sport": sport, "dport": dport, "packets": pkt_cnt, "bytes": byte_cnt}
        for src_ip, dst_ip, sport, dport, pkt_cnt, byte_cnt in conn_by_bytes
    ]

    if progress_callback:
        progress_callback(100)

    return findings


# ─── Generador de reporte HTML ────────────────────────────────────────────────

def generate_html_report(findings: dict, output_path: str):
    RISK_C = {
        "CRITICAL": "#ff4757",
        "HIGH":     "#ff6b35",
        "MEDIUM":   "#ffd93d",
        "LOW":      "#00ff88",
        "INFO":     "#00d4ff",
    }

    meta     = findings["metadata"]
    stats    = findings["statistics"]
    all_f    = findings["findings"]
    top_ips  = findings["top_ips"]

    order   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    all_f_s = sorted(all_f, key=lambda x: order.index(x["risk"]))

    overall = "INFO"
    for f in all_f_s:
        if order.index(f["risk"]) < order.index(overall):
            overall = f["risk"]
    if not all_f:
        overall = "INFO"

    findings_html = ""
    for f in all_f_s:
        col = RISK_C.get(f["risk"], "#00d4ff")
        ex_block = ""
        if f.get("examples"):
            ex_html = f["examples"].replace("\n", "<br>").replace("  •", "&nbsp;&nbsp;•")
            ex_block = f'<div class="examples">{ex_html}</div>'

        findings_html += f"""
<div class="card">
  <div class="card-head">
    <span class="card-title">{f["title"]}</span>
    <span class="badge" style="color:{col};border-color:{col}40;background:{col}12">{f["risk"]}</span>
  </div>
  <p class="desc">{f["description"]}</p>
  {ex_block}
  <div class="info-row cause">
    <span class="tag">⚠ Causa probable</span>
    <span>{f["cause"]}</span>
  </div>
  <div class="info-row rec">
    <span class="tag">✓ Recomendación</span>
    <span>{f["recommendation"]}</span>
  </div>
</div>"""

    if not findings_html:
        findings_html = '<div class="ok-msg">✓ No se detectaron amenazas significativas en esta captura.</div>'

    ip_rows = "".join(
        f'<tr><td class="mono">{x["ip"]}</td><td>{x["packets"]:,}</td><td>{x["bytes"]/1048576:.2f} MB</td></tr>'
        for x in top_ips
    )
    
    # Tabla de conexiones TCP
    conn_rows = ""
    if "top_connections" in findings and findings["top_connections"]:
        conn_rows = "".join(
            f'<tr><td class="mono">{c["src"]}:{c["sport"]}</td><td class="mono">{c["dst"]}:{c["dport"]}</td><td>{c["packets"]:,}</td><td>{c["bytes"]/1048576:.2f} MB</td></tr>'
            for c in findings["top_connections"][:15]
        )
        conn_html = f"""
<div class="sec-title">Top Conexiones TCP (por volumen)</div>
<table>
  <thead><tr><th>Origen</th><th>Destino</th><th>Paquetes</th><th>Datos</th></tr></thead>
  <tbody>{conn_rows}</tbody>
</table>"""
    else:
        conn_html = ""

    oc = RISK_C.get(overall, "#00d4ff")

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>PCAP Report — {meta['file']}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;700;800&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#060a0f;color:#dce6f0;font-family:'Syne',sans-serif;padding:2.5rem 1.5rem;min-height:100vh}}
body::before{{content:'';position:fixed;top:0;left:0;right:0;bottom:0;background:radial-gradient(ellipse at 20% 0%, #00d4ff08 0%, transparent 60%),radial-gradient(ellipse at 80% 100%, #bd93f908 0%, transparent 60%);pointer-events:none}}
.wrap{{max-width:980px;margin:0 auto;position:relative}}
header{{margin-bottom:2.5rem;padding-bottom:1.5rem;border-bottom:1px solid #1e293b}}
.logo{{font-family:'JetBrains Mono',monospace;color:#00d4ff;font-size:.85rem;letter-spacing:4px;margin-bottom:.75rem;opacity:.8}}
h1{{font-size:2rem;font-weight:800;letter-spacing:-0.5px;line-height:1.2}}
.sub{{color:#64748b;font-size:.85rem;margin-top:.5rem;font-family:'JetBrains Mono',monospace}}
.pill{{display:inline-flex;align-items:center;gap:.4rem;padding:.35rem 1rem;border-radius:2rem;font-size:.8rem;font-weight:700;border:1px solid;margin-top:1rem;letter-spacing:1px}}
.sec-title{{font-size:.7rem;font-weight:700;letter-spacing:3px;color:#64748b;text-transform:uppercase;margin:2.5rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid #1e293b}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;margin-bottom:.5rem}}
.stat{{background:#0b111a;border:1px solid #1e293b;border-radius:.5rem;padding:1.1rem;text-align:center;transition:border-color .2s}}
.stat:hover{{border-color:#00d4ff30}}
.sv{{font-size:1.9rem;font-weight:800;color:#00d4ff;font-family:'JetBrains Mono',monospace;letter-spacing:-1px}}
.sl{{font-size:.68rem;color:#64748b;margin-top:.25rem;letter-spacing:1px;text-transform:uppercase}}
.card{{background:#0b111a;border:1px solid #1e293b;border-radius:.6rem;padding:1.25rem;margin-bottom:.875rem;transition:border-color .2s}}
.card:hover{{border-color:#1e3a5f}}
.card-head{{display:flex;justify-content:space-between;align-items:center;margin-bottom:.75rem;gap:1rem}}
.card-title{{font-size:.95rem;font-weight:700}}
.badge{{padding:.2rem .7rem;border-radius:1rem;font-size:.7rem;font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:1px;border:1px solid;white-space:nowrap}}
.desc{{color:#94a3b8;font-size:.85rem;line-height:1.6;margin-bottom:.75rem}}
.examples{{background:#060a0f;border:1px solid #1e293b;border-radius:.4rem;padding:.75rem 1rem;font-family:'JetBrains Mono',monospace;font-size:.75rem;color:#94a3b8;margin-bottom:.75rem;line-height:1.7}}
.info-row{{padding:.55rem .85rem;border-radius:.375rem;font-size:.82rem;line-height:1.5;margin-bottom:.4rem}}
.info-row span{{display:inline}}
.tag{{font-weight:700;margin-right:.5rem}}
.cause{{background:#ff475710;border-left:2px solid #ff4757}}
.rec{{background:#00ff8810;border-left:2px solid #00ff88}}
.cause .tag{{color:#ff7a85}}
.rec .tag{{color:#00ff88}}
.ok-msg{{text-align:center;padding:2.5rem;color:#00ff88;font-size:1rem;background:#00ff8808;border:1px solid #00ff8820;border-radius:.6rem}}
table{{width:100%;border-collapse:collapse;background:#0b111a;border:1px solid #1e293b;border-radius:.6rem;overflow:hidden}}
th{{background:#0f1720;padding:.75rem 1rem;text-align:left;font-size:.68rem;text-transform:uppercase;letter-spacing:2px;color:#64748b;font-weight:600}}
td{{padding:.65rem 1rem;font-size:.82rem;border-top:1px solid #1e293b;color:#94a3b8}}
tr:hover td{{background:#0f1720;color:#dce6f0}}
.mono{{font-family:'JetBrains Mono',monospace;font-size:.78rem}}
footer{{text-align:center;color:#334155;font-size:.72rem;margin-top:3rem;padding-top:1rem;border-top:1px solid #1e293b;font-family:'JetBrains Mono',monospace;letter-spacing:1px}}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="logo">◈ PCAP ANALYZER</div>
  <h1>Network Forensic Report</h1>
  <div class="sub">Archivo: {meta['file']} &nbsp;·&nbsp; {meta['analyzed_at']}</div>
  <div class="pill" style="color:{oc};border-color:{oc}50;background:{oc}12">
    RIESGO GENERAL: {overall}
  </div>
</header>

<div class="sec-title">Estadísticas generales</div>
<div class="stats">
  <div class="stat"><div class="sv">{stats['total_packets']:,}</div><div class="sl">Paquetes</div></div>
  <div class="stat"><div class="sv">{stats['unique_ips']:,}</div><div class="sl">IPs únicas</div></div>
  <div class="stat"><div class="sv">{stats['dns_queries']:,}</div><div class="sl">Consultas DNS</div></div>
  <div class="stat"><div class="sv">{stats['unique_dns_domains']:,}</div><div class="sl">Dominios únicos</div></div>
  <div class="stat"><div class="sv">{stats['tcp_retransmissions']:,}</div><div class="sl">Retransm. TCP</div></div>
  <div class="stat"><div class="sv">{len(all_f)}</div><div class="sl">Hallazgos</div></div>
</div>

<div class="sec-title">Hallazgos de seguridad ({len(all_f)})</div>
{findings_html}
{conn_html}

<div class="sec-title">Top IPs por tráfico</div>
<table>
  <thead><tr><th>Dirección IP</th><th>Paquetes</th><th>Datos enviados</th></tr></thead>
  <tbody>{ip_rows}</tbody>
</table>

<footer>PCAP ANALYZER &nbsp;·&nbsp; Generado {meta['analyzed_at']} &nbsp;·&nbsp; Uso educativo y análisis de seguridad</footer>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ─── Interfaz gráfica ─────────────────────────────────────────────────────────

class PCAPAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PCAP Analyzer")
        self.configure(bg=C["bg"])
        self.geometry("900x680")
        self.minsize(740, 560)
        self.resizable(True, True)

        self.pcap_file   = tk.StringVar()
        self.report_path = None
        self._setup_styles()
        self._build_ui()
        self._check_deps()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure(
            "Cyber.Horizontal.TProgressbar",
            troughcolor=C["bg3"], background=C["accent"],
            bordercolor=C["border"], lightcolor=C["accent"], darkcolor=C["accent"],
        )
        style.configure("Dark.TNotebook", background=C["bg"], bordercolor=C["border"])
        style.configure(
            "Dark.TNotebook.Tab",
            background=C["bg3"], foreground=C["muted"],
            padding=[14, 5], font=("Segoe UI", 9),
        )
        style.map(
            "Dark.TNotebook.Tab",
            background=[("selected", C["bg2"])],
            foreground=[("selected", C["text"])],
        )

    def _check_deps(self):
        if not SCAPY_OK:
            self._log("⚠  Scapy no está instalado.", "warn")
            self._log("   Windows: python -m pip install scapy", "warn")
            self._log("   Linux/macOS: python3 -m pip install scapy", "warn")
            self._log("   Considera ejecutar setup.bat (Windows) o setup.sh (Linux/macOS)", "muted")
            self._log("   Luego reinicia esta aplicación.", "muted")

    def _build_ui(self):
        # ── Header ──────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=C["bg"])
        hdr.pack(fill="x", padx=26, pady=(18, 14))

        tk.Label(hdr, text="◈ PCAP ANALYZER", bg=C["bg"], fg=C["accent"],
                 font=("Consolas", 11, "bold")).pack(anchor="w")
        tk.Label(hdr, text="Herramienta de análisis forense de red",
                 bg=C["bg"], fg=C["muted"], font=("Segoe UI", 9)).pack(anchor="w")

        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        # ── Selector de archivo ─────────────────────────────────────────────
        fbar = tk.Frame(self, bg=C["bg2"])
        fbar.pack(fill="x")

        inner = tk.Frame(fbar, bg=C["bg2"])
        inner.pack(fill="x", padx=26, pady=14)

        tk.Label(inner, text="ARCHIVO PCAP / PCAPNG", bg=C["bg2"], fg=C["muted"],
                 font=("Consolas", 7, "bold")).pack(anchor="w")

        row = tk.Frame(inner, bg=C["bg2"])
        row.pack(fill="x", pady=(5, 0))

        self.entry = tk.Entry(
            row, textvariable=self.pcap_file,
            bg=C["bg3"], fg=C["text"], font=("Consolas", 9),
            relief="flat", bd=0, insertbackground=C["accent"],
            highlightthickness=1, highlightbackground=C["border"],
            highlightcolor=C["accent"],
        )
        self.entry.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 8))
        self._mk_btn(row, "Explorar", self._browse, C["accent"]).pack(side="left")

        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        # ── Barra de acción ─────────────────────────────────────────────────
        act = tk.Frame(self, bg=C["bg"])
        act.pack(fill="x", padx=26, pady=12)

        self.btn_analyze = self._mk_btn(act, "  ▶  Analizar  ", self._start, C["green"])
        self.btn_analyze.pack(side="left")

        self.btn_report = self._mk_btn(act, "  ↗  Abrir reporte  ", self._open_report, C["accent"])
        self.btn_report.pack(side="left", padx=(8, 0))
        self.btn_report.config(state="disabled")

        # ── Barra de progreso ───────────────────────────────────────────────
        self.prog_var = tk.IntVar(value=0)
        self.prog = ttk.Progressbar(
            self, variable=self.prog_var, maximum=100,
            mode="determinate", style="Cyber.Horizontal.TProgressbar",
        )
        self.prog.pack(fill="x", padx=26, pady=(0, 2))

        # ── Notebook ────────────────────────────────────────────────────────
        nb_wrap = tk.Frame(self, bg=C["bg"])
        nb_wrap.pack(fill="both", expand=True, padx=26, pady=(8, 0))

        self.nb = ttk.Notebook(nb_wrap, style="Dark.TNotebook")
        self.nb.pack(fill="both", expand=True)

        # Tab consola
        self.tab_log = tk.Frame(self.nb, bg=C["bg2"])
        self.nb.add(self.tab_log, text="  📋 Consola  ")
        self.log_txt = self._mk_text(self.tab_log)
        for tag, fg, bold in [
            ("info",   C["text"],   False),
            ("ok",     C["green"],  False),
            ("warn",   C["yellow"], False),
            ("err",    C["red"],    False),
            ("accent", C["accent"], False),
            ("muted",  C["muted"],  False),
            ("crit",   C["red"],    True),
            ("high",   C["orange"], True),
            ("med",    C["yellow"], True),
            ("sep",    C["border"], False),
        ]:
            font = ("Consolas", 9, "bold") if bold else ("Consolas", 9)
            self.log_txt.tag_config(tag, foreground=fg, font=font)

        # Tab hallazgos
        self.tab_find = tk.Frame(self.nb, bg=C["bg2"])
        self.nb.add(self.tab_find, text="  🔍 Hallazgos  ")
        self.find_txt = self._mk_text(self.tab_find)
        for tag, fg, fsize, bold in [
            ("h1",    C["accent"],  10, True),
            ("h2",    C["muted"],   8,  True),
            ("body",  C["text"],    9,  False),
            ("cause", C["yellow"],  9,  False),
            ("rec",   C["green"],   9,  False),
            ("mono",  C["muted"],   8,  False),
            ("crit",  C["red"],     9,  True),
            ("high",  C["orange"],  9,  True),
            ("med",   C["yellow"],  9,  True),
            ("low",   C["green"],   9,  True),
            ("info",  C["accent"],  9,  True),
            ("sep",   C["border"],  9,  False),
        ]:
            font = ("Consolas" if tag == "mono" else "Segoe UI", fsize, "bold" if bold else "normal")
            self.find_txt.tag_config(tag, foreground=fg, font=font)

        # ── Status bar ──────────────────────────────────────────────────────
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x", pady=(8, 0))
        self.status = tk.StringVar(value="Listo — selecciona un archivo .pcap o .pcapng para comenzar")
        tk.Label(self, textvariable=self.status, bg=C["bg"], fg=C["muted"],
                 font=("Segoe UI", 8), anchor="w").pack(fill="x", padx=26, pady=6)

    def _mk_text(self, parent):
        frame = tk.Frame(parent, bg=C["bg2"])
        frame.pack(fill="both", expand=True)
        txt = tk.Text(
            frame, bg=C["bg2"], fg=C["text"], font=("Consolas", 9),
            relief="flat", bd=0, state="disabled", wrap="word",
            selectbackground=C["accent"], highlightthickness=0, padx=10, pady=8,
        )
        sb = ttk.Scrollbar(frame, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)
        return txt

    def _mk_btn(self, parent, text, cmd, color):
        return tk.Button(
            parent, text=text, command=cmd,
            bg=darken_hex(color, 0.10), fg=color,
            font=("Segoe UI", 9, "bold"),
            relief="flat", bd=0, cursor="hand2",
            activebackground=darken_hex(color, 0.21), activeforeground=color,
            padx=14, pady=6,
            highlightthickness=1, highlightbackground=darken_hex(color, 0.33),
        )

    def _log(self, msg, tag="info"):
        t = self.log_txt
        t.configure(state="normal")
        t.insert("end", msg + "\n", tag)
        t.see("end")
        t.configure(state="disabled")

    def _browse(self):
        p = filedialog.askopenfilename(
            title="Seleccionar captura PCAP",
            filetypes=[("PCAP / PCAPNG", "*.pcap *.pcapng *.cap"), ("Todos", "*.*")],
        )
        if p:
            self.pcap_file.set(p)
            self._log(f"Archivo cargado: {os.path.basename(p)}", "accent")

    def _start(self):
        if not SCAPY_OK:
            messagebox.showerror("Scapy no encontrado", 
                "No se encontró Scapy.\n\nEjecuta el setup (Windows: setup.bat, Linux: bash setup.sh)\n\nO instala manualmente:\nWindows: python -m pip install scapy\nLinux/macOS: python3 -m pip install scapy")
            return
        path = self.pcap_file.get().strip()
        if not path:
            messagebox.showwarning("Sin archivo", "Selecciona un archivo PCAP primero.")
            return
        if not os.path.exists(path):
            messagebox.showerror("No encontrado", f"El archivo no existe:\n{path}")
            return

        self.btn_analyze.config(state="disabled")
        self.btn_report.config(state="disabled")
        self.prog_var.set(0)
        self.report_path = None

        for t in (self.log_txt, self.find_txt):
            t.configure(state="normal")
            t.delete("1.0", "end")
            t.configure(state="disabled")

        self.nb.select(0)
        self._log("━" * 52, "sep")
        self._log(" ◈  PCAP ANALYZER — Iniciando análisis...", "accent")
        self._log("━" * 52, "sep")
        self._log(f" Archivo : {os.path.basename(path)}", "info")
        self._log(f" Tamaño  : {os.path.getsize(path)/1024:.1f} KB", "muted")
        self._log(" Cargando paquetes...", "info")
        self.status.set("Cargando paquetes...")

        threading.Thread(target=self._worker, args=(path,), daemon=True).start()

    def _worker(self, path):
        try:
            def prog(v):
                self.prog_var.set(v)
                msgs = {0: "Cargando...", 30: "Analizando DNS...",
                        50: "Analizando TCP/UDP...", 72: "Evaluando patrones...",
                        90: "Generando hallazgos..."}
                for k in sorted(msgs.keys(), reverse=True):
                    if v >= k:
                        self.after(0, lambda m=msgs[k], pv=v: self.status.set(f"{m}  {pv}%"))
                        break

            data = analyze_pcap(path, progress_callback=prog)

            dl = Path.home() / "Downloads"
            dl.mkdir(exist_ok=True)
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            rp   = str(dl / f"pcap_report_{ts}.html")
            generate_html_report(data, rp)
            self.report_path = rp

            self.after(0, self._done, data)
        except Exception as e:
            self.after(0, self._err, str(e))

    def _done(self, data):
        self.btn_analyze.config(state="normal")
        self.btn_report.config(state="normal")
        self.prog_var.set(100)

        meta  = data["metadata"]
        all_f = data["findings"]
        stats = data["statistics"]
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        all_f_s = sorted(all_f, key=lambda x: order.index(x["risk"]))

        self._log("", "sep")
        self._log(f"✓  Análisis completado — {meta['total_packets']:,} paquetes procesados", "ok")
        self._log(f"✓  Reporte HTML guardado en Descargas", "ok")
        self._log(f"   {os.path.basename(self.report_path)}", "muted")
        self._log("", "sep")
        self._log(f"── ESTADÍSTICAS ──────────────────────────────────────", "sep")
        self._log(f"  Paquetes totales      : {stats['total_packets']:,}", "info")
        self._log(f"  IPs únicas            : {stats['unique_ips']:,}", "info")
        self._log(f"  Conexiones TCP        : {stats.get('tcp_connections', 0):,}", "info")
        self._log(f"  Consultas DNS         : {stats['dns_queries']:,}", "info")
        self._log(f"  Dominios únicos DNS   : {stats['unique_dns_domains']:,}", "info")
        self._log(f"  Retransmisiones TCP   : {stats['tcp_retransmissions']:,}", "info")
        
        # Mostrar conexiones TCP principales
        if "top_connections" in data and data["top_connections"]:
            self._log("", "sep")
            self._log(f"── TOP CONEXIONES TCP (por volumen) ────────────────", "sep")
            for conn in data["top_connections"][:8]:
                self._log(f"  {conn['src']}:{conn['sport']} → {conn['dst']}:{conn['dport']}  |  {conn['packets']} paqts  |  {conn['bytes']/1024:.1f} KB", "info")
        
        self._log("", "sep")

        if not all_f_s:
            self._log("  ✓  Sin amenazas detectadas.", "ok")
        else:
            self._log(f"── HALLAZGOS ({len(all_f_s)}) ───────────────────────────────────", "sep")
            tag_map = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med",
                       "LOW": "ok", "INFO": "accent"}
            for f in all_f_s:
                t = tag_map.get(f["risk"], "info")
                self._log(f"  [{f['risk']:8}]  {f['title']}", t)

            self._log("", "sep")
            self._log("── CAUSAS Y ACCIONES ─────────────────────────────────", "sep")
            for f in all_f_s:
                self._log(f"\n● {f['title']}", "accent")
                self._log(f"  ⚠ {f['cause'][:130]}...", "warn")
                self._log(f"  ✓ {f['recommendation'][:130]}", "ok")

        self._log("\n" + "━" * 52, "sep")
        self._populate_findings(data)
        self.nb.select(1)
        self.status.set(
            f"Análisis completado — {len(all_f)} hallazgo(s) — Reporte guardado en Descargas"
        )

    def _populate_findings(self, data):
        t = self.find_txt
        t.configure(state="normal")
        t.delete("1.0", "end")

        meta  = data["metadata"]
        stats = data["statistics"]
        all_f = data["findings"]
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        all_f_s = sorted(all_f, key=lambda x: order.index(x["risk"]))

        t.insert("end", f"ANÁLISIS DE SEGURIDAD — {meta['file']}\n", "h1")
        t.insert("end", f"Fecha: {meta['analyzed_at']}\n\n", "h2")

        t.insert("end", "── ESTADÍSTICAS ───────────────────────────────────────\n", "sep")
        for label, val in [
            ("Paquetes totales",    f"{stats['total_packets']:,}"),
            ("IPs únicas",          f"{stats['unique_ips']:,}"),
            ("Conexiones TCP",      f"{stats.get('tcp_connections', 0):,}"),
            ("Consultas DNS",       f"{stats['dns_queries']:,}"),
            ("Dominios DNS únicos", f"{stats['unique_dns_domains']:,}"),
            ("Retransm. TCP",       f"{stats['tcp_retransmissions']:,}"),
        ]:
            t.insert("end", f"  {label:<28}", "h2")
            t.insert("end", f"{val}\n", "body")

        # Top conexiones TCP
        if "top_connections" in data and data["top_connections"]:
            t.insert("end", "\n── TOP CONEXIONES TCP (por volumen) ────────────────\n", "sep")
            for conn in data["top_connections"][:10]:
                t.insert("end", f"  {conn['src']}:{conn['sport']} → {conn['dst']}:{conn['dport']:<6}", "mono")
                t.insert("end", f"  {conn['packets']:>6} paqts  {conn['bytes']/1024:>7.1f} KB\n", "body")

        t.insert("end", f"\n── HALLAZGOS ({len(all_f_s)}) ────────────────────────────────────\n\n", "sep")

        if not all_f_s:
            t.insert("end", "  ✓ No se detectaron amenazas significativas.\n", "rec")
        else:
            rtag = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med",
                    "LOW": "low", "INFO": "info"}
            for f in all_f_s:
                rt = rtag.get(f["risk"], "info")
                t.insert("end", f"  [{f['risk']}] ", rt)
                t.insert("end", f"{f['title']}\n", "h1")
                t.insert("end", f"  {f['description']}\n\n", "body")

                if f.get("examples"):
                    t.insert("end", "  Ejemplos detectados:\n", "h2")
                    for line in f["examples"].split("\n"):
                        if line.strip():
                            t.insert("end", f"  {line}\n", "mono")
                    t.insert("end", "\n", "body")

                t.insert("end", "  ⚠ CAUSA:  ", "h2")
                t.insert("end", f"{f['cause']}\n\n", "cause")
                t.insert("end", "  ✓ ACCIÓN: ", "h2")
                t.insert("end", f"{f['recommendation']}\n", "rec")
                t.insert("end", "\n" + "─" * 56 + "\n\n", "sep")

        t.insert("end", "\n  TOP IPs POR TRÁFICO\n", "h2")
        t.insert("end", "  ─────────────────────────────────────────────\n", "sep")
        for x in data["top_ips"]:
            t.insert("end", f"  {x['ip']:<20}", "mono")
            t.insert("end", f"{x['packets']:>7,} paqts   {x['bytes']/1048576:>6.2f} MB\n", "body")

        t.configure(state="disabled")
        t.see("1.0")

    def _err(self, msg):
        self.btn_analyze.config(state="normal")
        self.prog_var.set(0)
        self._log(f"✗ Error: {msg}", "err")
        self.status.set(f"Error: {msg}")
        messagebox.showerror("Error de análisis", msg)

    def _open_report(self):
        if self.report_path and os.path.exists(self.report_path):
            webbrowser.open(f"file:///{self.report_path}")
        else:
            messagebox.showinfo("Sin reporte", "Analiza un archivo primero.")


if __name__ == "__main__":
    app = PCAPAnalyzer()
    app.mainloop()