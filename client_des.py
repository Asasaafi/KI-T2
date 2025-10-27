import socket
import threading
from crypto_utils import key_hex_to_bytes, encrypt_des_cbc, decrypt_des_cbc, to_hex, from_hex

def handle_receive(conn, key):
    """Terima pesan terenkripsi dari server"""
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                print("Server terputus.")
                break

            iv_hex, ct_hex = data.decode().split("|")
            iv = from_hex(iv_hex)
            ct = from_hex(ct_hex)
            plaintext = decrypt_des_cbc(key, iv, ct).decode()
            print(f"\n[Server]: {plaintext}")
        except Exception as e:
            print("Terjadi kesalahan saat menerima:", e)
            break

def main():
    print("=== CLIENT DES CHAT ===")
    host = input("Masukkan IP server: ")
    port = int(input("Masukkan port (default 9000): ") or "9000")
    hexkey = input("Masukkan key DES (16 hex chars): ")
    key = key_hex_to_bytes(hexkey)

    conn =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host, port))
    print(f"Terhubung ke server {host}:{port}")

    # Jalankan thread untuk menerima pesan
    threading.Thread(target=handle_receive, args=(conn, key), daemon=True).start()

    # Kirim pesan ke server
    while True:
        msg = input("> ")
        if msg.lower() == "exit":
            print("Menutup koneksi...")
            conn.close()
            break
        iv, ct = encrypt_des_cbc(key, msg.encode())
        conn.send(f"{to_hex(iv)}|{to_hex(ct)}".encode())

if __name__ == "__main__":
    main()