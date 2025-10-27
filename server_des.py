import socket
import base64
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

BIND_ADDR = ('192.168.142.46', 65489)
KEY = b'mysecret'

def des_encrypt(msg, mode, iv=None):
    des = DES.new(KEY, DES.MODE_CBC, iv) if mode == 'CBC' else DES.new(KEY, DES.MODE_ECB)
    return base64.b64encode(des.encrypt(pad(msg.encode(), DES.block_size))).decode()

def des_decrypt(enc, mode, iv=None):
    des = DES.new(KEY, DES.MODE_CBC, iv) if mode == 'CBC' else DES.new(KEY, DES.MODE_ECB)
    return unpad(des.decrypt(base64.b64decode(enc)), DES.block_size).decode()

def serve():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # ini penting agar tidak error
        server.bind(BIND_ADDR)
        server.listen(1)
        print(f"Server berjalan di {BIND_ADDR[0]}:{BIND_ADDR[1]}")
        print("Menunggu koneksi dari client...")

        conn, addr = server.accept()
        print(f"Tersambung dari {addr}")

        with conn:
            mode = conn.recv(64).decode().strip()
            print(f"Mode komunikasi: {mode}")

            while True:
                data = conn.recv(4096)
                if not data:
                    print("Client keluar.")
                    break

                lines = dict(line.split("=", 1) for line in data.decode().split("\n") if "=" in line)
                iv_in = None if lines.get("IV") == "-" else base64.b64decode(lines.get("IV"))
                plain_in = des_decrypt(lines.get("DATA"), lines.get("MODE"), iv_in)

                print("\nPesan diterima:")
                print(f"Teks Asli      : {lines.get('PLAIN')}")
                print(f"Terenkripsi    : {lines.get('DATA')}")
                if mode == "CBC":
                    print(f"IV             : {lines.get('IV')}")
                print(f"Hasil Dekripsi : {plain_in}")

                reply_text = input("Balasan: ")
                if reply_text.lower() == "exit":
                    print("Koneksi ditutup oleh server.")
                    break

                iv_out = os.urandom(8) if mode == 'CBC' else None
                reply_cipher = des_encrypt(reply_text, mode, iv_out)

                response = "\n".join([
                    f"MODE={mode}",
                    f"IV={base64.b64encode(iv_out).decode() if iv_out else '-'}",
                    f"DATA={reply_cipher}",
                    f"PLAIN={reply_text}"
                ])
                conn.send(response.encode())

if __name__ == "__main__":
    serve()