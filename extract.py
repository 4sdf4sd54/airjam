import binascii
import struct
from scapy.all import rdpcap, EAPOL, Dot11, Raw

def extract_handshake_info(pcap_path, ssid_required=True):
    """
    Extracts handshake info from a .pcap file containing WPA/WPA2 handshakes.

    Args:
        pcap_path (str): Path to the .pcap file.
        ssid_required (bool): If True, raises an exception if SSID is not found.

    Returns:
        dict: Handshake information with keys:
            - bssid (AP MAC)
            - sta (Client MAC)
            - anonce
            - snonce
            - eapol_msg
            - mic
            - ssid
            - eapol (entire EAPOL payload)
    """
    packets = rdpcap(pcap_path)
    handshake = {
        'bssid': None,
        'sta': None,
        'anonce': None,
        'snonce': None,
        'eapol_msg': None,
        'mic': None,
        'ssid': None,
        'eapol': None
    }
    ssid = None
    eapol_msgs = []
    bssid = None
    sta = None

    # First, find SSID from beacon/probe response
    for pkt in packets:
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype in [8, 5]:  # Beacon or Probe Response
                if hasattr(pkt, 'info') and pkt.info:
                    ssid = pkt.info.decode(errors='ignore')
                    handshake['ssid'] = ssid
                    break

    if ssid_required and not handshake['ssid']:
        raise Exception("SSID not found in the capture. It is required.")

    # Now, extract EAPOL handshakes
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            eapol = pkt.getlayer(EAPOL)
            dot11 = pkt.getlayer(Dot11)
            src = dot11.addr2
            dst = dot11.addr1

            # Identify BSSID and STA by EAPOL direction (STA <-> AP)
            if not bssid or not sta:
                if dot11.FCfield & 0x01:  # To DS
                    bssid = dst
                    sta = src
                elif dot11.FCfield & 0x02:  # From DS
                    bssid = src
                    sta = dst

            raw_eapol = bytes(eapol)
            eapol_msgs.append((pkt, raw_eapol, src, dst))

    # Extract required info from EAPOL messages
    for pkt, eapol_bytes, src, dst in eapol_msgs:
        # EAPOL-Key descriptor is at offset 1, key info at offset 5-6
        if len(eapol_bytes) < 100:
            continue  # skip malformed
        key_info = struct.unpack('>H', eapol_bytes[5:7])[0]
        is_m2 = key_info & 0b100000000 and not (key_info & 0b10000)
        is_m4 = key_info & 0b100000000 and (key_info & 0b10000)
        # Message 2 or 4 (from client, includes SNonce)
        if is_m2 or is_m4:
            handshake['eapol_msg'] = 2 if is_m2 else 4
            handshake['sta'] = src
            handshake['bssid'] = dst if is_m2 else src
            handshake['eapol'] = binascii.hexlify(eapol_bytes).decode()
            # SNonce at 17:49 (32 bytes)
            handshake['snonce'] = binascii.hexlify(eapol_bytes[17:49]).decode()
            handshake['mic'] = binascii.hexlify(eapol_bytes[81:97]).decode()
            break  # found message 2 or 4

    # Find ANonce from message 1 or 3 (from AP)
    for pkt, eapol_bytes, src, dst in eapol_msgs:
        key_info = struct.unpack('>H', eapol_bytes[5:7])[0]
        is_m1 = key_info & 0b100000000 and not (key_info & 0b10000)
        is_m3 = key_info & 0b100000000 and (key_info & 0b10000)
        if is_m1 or is_m3:
            handshake['anonce'] = binascii.hexlify(eapol_bytes[17:49]).decode()
            break

    return handshake

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python extract_handshake_info.py <handshake.pcap>")
        sys.exit(1)
    info = extract_handshake_info(sys.argv[1])
    for k, v in info.items():
        print(f"{k}: {v}")
