# KI-T2

| NRP | Nama |
|:-----------:|:--------:|
| 5025231202  | Lailatul Annisa Fitriana  |

Program ini menampilkan komunikasi dua device (client dan server) menggunakan algoritma DES (Data Encryption Standard).
Keduanya saling mengirim dan menerima pesan terenkripsi secara bergantian (vice versa).

## Struktur File

client_des.py : program sisi client
server_des.py : program sisi server
crypto_utils.py : fungsi untuk enkripsi dan dekripsi DES

## Cara Menjalankan

Install library yang diperlukan:
````
pip install pycryptodome
````
Untuk key
````
python crypto_utils.py
````

Jalankan server lebih dulu:
````
python server_des.py
````

Jalankan client di terminal lain:
````
python client_des.py
````

Ketik pesan di client, maka pesan akan terenkripsi sebelum dikirim dan didekripsi di sisi penerima.

Catatan
- Kunci DES diketahui oleh kedua device.
- Menggunakan mode CBC.
- Komunikasi bisa berjalan dua arah (client ⇄ server).