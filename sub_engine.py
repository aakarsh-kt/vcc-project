#!/usr/bin/env python3
import socket

HOST = '0.0.0.0'
PORT = 9102

def start_sub_engine():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[SUB_ENGINE] Listening on {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024).decode().strip()
            print(f"[SUB_ENGINE] Received: {data}")
            try:
                parts = data.split(":")
                if len(parts) != 3 or parts[0] != "sub":
                    conn.send(b"Invalid format. Use sub:<num1>:<num2>\n")
                    continue
                _, n1, n2 = parts
                result = float(n1) - float(n2)
                conn.send(f"Result: {result}".encode())
            except Exception as e:
                conn.send(f"Error: {e}".encode())

if __name__ == '__main__':
    start_sub_engine()