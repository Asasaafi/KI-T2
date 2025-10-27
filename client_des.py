import socket
import base64
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

SERVER_ADDR = ('192.168.142.46', 65489)
KEY = b'mysecret'

def des_encrypt(msg, mode, iv=None):
    des = DES.new(KEY, DES.MODE_CBC, iv) if mode == 'CBC' else DES.new(KEY, DES.MODE_ECB)
    return base64.b64encode(des.encrypt(pad(msg.encode(), DES.block_size))).decode()

def des_decrypt(enc, mode, iv=None):
    des = DES.new(KEY, DES.MODE_CBC, iv) if mode == 'CBC' else DES.new(KEY, DES.MODE_ECB)
    return unpad(des.decrypt(base64.b64decode(enc)), DES.block_size).decode()

def client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(SERVER_ADDR)
        print(f"Tersambung ke server {SERVER_ADDR}")

        mode = input("Pilih mode (CBC / ECB): ").strip().upper()
        if mode not in ['CBC', 'ECB']:
            print("Mode tidak valid! Gunakan CBC atau ECB.")
            return

        s.send(mode.encode())

        while True:
            msg = input("Kirim pesan: ")
            if msg.lower() == "exit":
                print("Koneksi ditutup oleh client.")
                break

            iv_out = os.urandom(8) if mode == 'CBC' else None
            cipher_text = des_encrypt(msg, mode, iv_out)

            payload = "\n".join([
                f"MODE={mode}",
                f"IV={base64.b64encode(iv_out).decode() if iv_out else '-'}",
                f"DATA={cipher_text}",
                f"PLAIN={msg}"
            ])
            s.send(payload.encode())

            # Terima balasan dari server
            data = s.recv(4096)
            if not data:
                print("Server telah menutup koneksi.")
                break

            lines = dict(line.split("=", 1) for line in data.decode().split("\n") if "=" in line)
            iv_in = None if lines.get("IV") == "-" else base64.b64decode(lines.get("IV"))
            decrypted = des_decrypt(lines.get("DATA"), lines.get("MODE"), iv_in)

            print("\nBalasan dari server:")
            print(f"Teks Asli      : {lines.get('PLAIN')}")
            print(f"Terenkripsi    : {lines.get('DATA')}")
            if mode == "CBC":
                print(f"IV             : {lines.get('IV')}")
            print(f"Hasil Dekripsi : {decrypted}\n")

if __name__ == "__main__":
    client()
