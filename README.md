# KI-T2

| NRP | Nama |
|:-----------:|:--------:|
| 5025231202  | Lailatul Annisa Fitriana  |

Program ini menampilkan komunikasi dua device (client dan server) menggunakan algoritma DES (Data Encryption Standard).
Keduanya saling mengirim dan menerima pesan terenkripsi secara bergantian (vice versa).

## Struktur File

client_des.py : program sisi client
server_des.py : program sisi server

## Cara Menjalankan

Install library yang diperlukan:
````
pip install pycryptodome
````
Untuk device server
````
python server_des.py
````

Untuk device client
````
python client_des.py
````
````