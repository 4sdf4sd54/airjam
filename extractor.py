import sys
from scapy.all import rdpcap, EAPOL, Dot11, Dot11Beacon, Dot11ProbeResp

def get_ssid(packets):
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            try:
                ssid = pkt.info.decode(errors='ignore')
                if ssid:
                    return ssid
            except Exception:
                continue
    return None

def extract_handshake_info(filename):
    packets = rdpcap(filename)
    ssid = get_ssid(packets)
    if not ssid:
        print("SSID not found! SSID is required.")
        sys.exit(2)

    ap_mac = None
    client_mac = None
    anonce = None
    snonce = None
    mic = None
    eapol2or4_raw = None

    for pkt in packets:
        if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
            dot11 = pkt.getlayer(Dot11)
            eapol = pkt.getlayer(EAPOL)
            eapol_raw = bytes(eapol)
            src = dot11.addr2
            dst = dot11.addr1
            bssid = dot11.addr3

            if len(eapol_raw) < 95:
                continue

            key_info = int.from_bytes(eapol_raw[5:7], 'big')
            mic_present = (key_info & (1 << 8)) != 0
            ack = (key_info & (1 << 7)) != 0
            install = (key_info & (1 << 6)) != 0

            # --- FIX: Prefer scapy field, else raw offset (17:49 is standard for WPA2, adjust if needed) ---
            if hasattr(eapol.payload, 'nonce') and isinstance(getattr(eapol.payload, 'nonce', None), bytes):
                nonce = eapol.payload.nonce.hex()
            else:
                nonce = eapol_raw[17:49].hex()

            mic_val = eapol_raw[81:97].hex()

            # Message 1: ANonce, from AP to STA, first seen!
            if not mic_present and ack and anonce is None:
                anonce = nonce
                ap_mac = src
                client_mac = dst

            # Message 2: SNonce + MIC, from client to AP
            elif mic_present and not ack and not install:
                if not snonce:
                    snonce = nonce
                if not mic:
                    mic = mic_val
                if not eapol2or4_raw:
                    eapol2or4_raw = eapol_raw.hex()
                    if not ap_mac:
                        ap_mac = bssid if bssid != src else dst
                    if not client_mac:
                        client_mac = src

    if not (anonce and snonce and mic and eapol2or4_raw and ssid and ap_mac and client_mac):
        print("Failed to extract all required handshake parameters.")
        print(f"SSID: {ssid if ssid else 'Not found'}")
        print(f"AP MAC: {ap_mac if ap_mac else 'Not found'}")
        print(f"Client MAC: {client_mac if client_mac else 'Not found'}")
        print(f"ANonce: {anonce if anonce else 'Not found'}")
        print(f"SNonce: {snonce if snonce else 'Not found'}")
        print(f"MIC: {mic if mic else 'Not found'}")
        print(f"EAPOL: {eapol2or4_raw if eapol2or4_raw else 'Not found'}")
        sys.exit(3)

    print(f"SSID: {ssid}")
    print(f"AP MAC (BSSID): {ap_mac}")
    print(f"Client MAC (STA): {client_mac}")
    print(f"ANonce: {anonce}")
    print(f"SNonce: {snonce}")
    print(f"MIC: {mic}")
    print(f"EAPOL (msg 2 or 4, raw hex): {eapol2or4_raw}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <handshake.pcap>")
        sys.exit(1)
    extract_handshake_info(sys.argv[1])
