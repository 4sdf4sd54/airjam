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

def zero_mic(eapol_raw):
    # Zero MIC field at offset 81-97 bytes (16 bytes)
    if len(eapol_raw) >= 97:
        return eapol_raw[:81] + b'\x00' * 16 + eapol_raw[97:]
    else:
        return eapol_raw

def format_hex_bytes(data, bytes_per_line=16):
    hex_str = data.hex()
    # Split into 2-char chunks (bytes)
    bytes_list = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    # Group bytes per line
    lines = []
    for i in range(0, len(bytes_list), bytes_per_line):
        line_bytes = bytes_list[i:i+bytes_per_line]
        lines.append(' '.join(line_bytes))
    return '\n'.join(lines)

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

            # Extract nonce from EAPOL (bytes 17-49)
            nonce = eapol_raw[17:49].hex()
            mic_val = eapol_raw[81:97].hex()

            # Message 1 of 4-way handshake: ANonce (from AP to Client)
            if not mic_present and ack and not install and anonce is None:
                anonce = nonce
                ap_mac = src
                client_mac = dst

            # Message 2 or 4: SNonce + MIC (from Client to AP)
            elif mic_present and snonce is None:
                snonce = nonce
                mic = mic_val
                # zero MIC field
                eapol_clean = zero_mic(eapol_raw)

                # Read EAPOL payload length (bytes 2 and 3)
                length = int.from_bytes(eapol_clean[2:4], 'big')
                total_len = 4 + length  # 4 bytes header + length field

                # Slice EAPOL to correct length to avoid trailing garbage
                if total_len <= len(eapol_clean):
                    eapol_clean = eapol_clean[:total_len]

                eapol2or4_raw = eapol_clean

                # Assign AP and client MAC if not already
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
        print(f"EAPOL (msg 2 or 4, raw hex): {'Not found'}")
        sys.exit(3)

    print(f"SSID: {ssid}")
    print(f"AP MAC (BSSID): {ap_mac}")
    print(f"Client MAC (STA): {client_mac}")
    print(f"ANonce: {anonce}")
    print(f"SNonce: {snonce}")
    print(f"MIC: {mic}")
    print(f"EAPOL (msg 2 or 4, raw hex, MIC zeroed):")
    print(format_hex_bytes(eapol2or4_raw))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <handshake.pcap>")
        sys.exit(1)
    extract_handshake_info(sys.argv[1])
