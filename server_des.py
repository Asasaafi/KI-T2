import socket
import threading
from crypto_utils import key_hex_to_bytes, encrypt_des_cbc, decrypt_des_cbc, to_hex, from_hex
import struct

def send_payload(conn, iv, ciphertext):
    """Kirim data dengan header panjang 2 byte"""
    payload = iv + ciphertext
    header = struct.pack('!H', len(payload))
    conn.sendall(header + payload)

def recv_payload(conn):
    """Terima data dan pecah menjadi (iv, ciphertext)"""
    header = conn.recv(2)
    if not header:
        return None, None
    (length,) = struct.unpack('!H', header)
    payload = conn.recv(length)
    if not payload:
        return None, None
    iv = payload[:8]
    ciphertext = payload[8:]
    return iv, ciphertext

def handle_receive(conn, key):
    """Thread untuk menerima pesan terenkripsi dari client"""
    while True:
        try:
            iv, ciphertext = recv_payload(conn)
            if not iv:
                print("Client terputus.")
                break
            plaintext = decrypt_des_cbc(key, iv, ciphertext)
            print(f"\n[Client]: {plaintext.decode()}")
        except Exception as e:
            print("Terjadi kesalahan saat menerima:", e)
            break

def main():
    host = input("Masukkan host: ") or "0.0.0.0"
    port = int(input("Masukkan port (default 9000): ") or "9000")
    hexkey = input("Masukkan key DES (16 hex chars): ")
    key = key_hex_to_bytes(hexkey)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    print(f"Menunggu koneksi di {host}:{port} ...")

    try:
        conn, addr = server.accept()
        print("Terhubung dengan:", addr)

        while True:
            data = conn.recv(4096)
            if not data:
                break

            iv_hex, ct_hex = data.decode().split("|")
            iv = from_hex(iv_hex)
            ct = from_hex(ct_hex)
            plaintext = decrypt_des_cbc(key, iv, ct).decode()
            print("Client:", plaintext)

            msg = input("Server: ").encode()
            iv, ct = encrypt_des_cbc(key, msg)
            conn.send(f"{to_hex(iv)}|{to_hex(ct)}".encode())

    except KeyboardInterrupt:
        print("\n[!] Server dihentikan oleh pengguna.")
    finally:
        try:
            conn.close()
        except:
            pass
        server.close()
        print("Koneksi ditutup.")

if __name__ == "__main__":
    main()