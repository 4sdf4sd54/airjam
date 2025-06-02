import binascii
import hashlib
import hmac

# Inputs (replace PASS_PHRASE with your candidate)
SSID = b"PEKLO"
AP_MAC = binascii.unhexlify("8401129a60ca".replace(":", ""))
CLIENT_MAC = binascii.unhexlify("a06faab513d4".replace(":", ""))
ANONCE = binascii.unhexlify("8cb77a3cbcaf860f4fd1866391620ea4aefa2df7304977514c3f1980e1efffc0")
SNONCE = binascii.unhexlify("97d6963ee90870ced98bdf61435e60e0527cfd3e596ad226b4d463b3224101df")
MIC = "e5d9c57e7a7409405c7210ca58e03404"

EAPOL_RAW_HEX = "0103007502010a0000000000000000000197d6963ee90870ced98bdf61435e60e0527cfd3e596ad226b4d463b3224101df0000000000000000000000000000000000000000000000000000000000000000e5d9c57e7a7409405c7210ca58e03404001630140100000fac040100000fac040100000fac020000"
CANDIDATE_PASSPHRASE = input("Enter passphrase to test: ").encode()

def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) // 160):
        hmacsha1 = hmac.new(key, A + b'\x00' + B + bytes([i]), hashlib.sha1)
        R += hmacsha1.digest()
        i += 1
    return R[:blen]

def main():
    # 1. Generate 4096 rounds PBKDF2-HMAC-SHA1 from passphrase and SSID
    pmk = hashlib.pbkdf2_hmac('sha1', CANDIDATE_PASSPHRASE, SSID, 4096, 32)
    
    # 2. Construct PTK
    B = min(AP_MAC, CLIENT_MAC) + max(AP_MAC, CLIENT_MAC) + min(ANONCE, SNONCE) + max(ANONCE, SNONCE)
    ptk = customPRF512(pmk, b"Pairwise key expansion", B)
    kck = ptk[:16]
    # 3. Prepare EAPOL frame with MIC zeroed out
    eapol = bytearray(binascii.unhexlify(EAPOL_RAW_HEX))
    # MIC is at offset 81 (16 bytes), zero it
    eapol[81:81+16] = b'\x00' * 16
    # 4. Calculate MIC (HMAC-SHA1-128)
    mic = hmac.new(kck, eapol, hashlib.sha1).digest()[:16]
    mic_hex = mic.hex()[:32]
    print(f"Calculated MIC: {mic_hex}")
    print(f"Expected MIC:   {MIC.lower()}")
    if mic_hex == MIC.lower():
        print("[+] Passphrase is CORRECT!")
    else:
        print("[-] Passphrase is incorrect.")

if __name__ == "__main__":
    main()
