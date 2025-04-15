#!/usr/bin/env python3
import socket

HOST = '0.0.0.0'
PORT = 9101

def start_add_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[ADD ENGINE] Listening on {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024).decode().strip()
            print(f"[ADD ENGINE] Received: {data}")
            try:
                op, n1, n2 = data.split(":")
                if op != "add":
                    conn.send(b"Unsupported operation\n")
                    continue
                result = float(n1) + float(n2)
                conn.send(f"Result: {result}".encode())
            except Exception as e:
                conn.send(f"Error: {e}".encode())

if __name__ == '__main__':
    start_add_server()