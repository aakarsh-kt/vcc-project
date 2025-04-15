#!/usr/bin/env python3
import ssl
import socket
import json
import logging

# PEP Configuration
HOST = '0.0.0.0'
PORT = 9000
ALLOWED_OPERATION = 'add'
ALLOWED_ROLES = ['admin', 'user']  # Only these roles can use this PEP

# Backend computation server (actual add engine)
ADD_ENGINE_IP = '34.57.41.136'  # Replace with real IP
ADD_ENGINE_PORT = 9101          # Port where add_engine.py is listening

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('pep_add.log'),
        logging.StreamHandler()
    ]
)

def forward_to_add_server(num1, num2):
    """
    Send numbers to the add engine and return the result.
    """
    try:
        with socket.create_connection((ADD_ENGINE_IP, ADD_ENGINE_PORT), timeout=5) as s:
            msg = f"add:{num1}:{num2}"
            s.sendall(msg.encode())
            response = s.recv(1024).decode().strip()
            logging.info(f"[ADD ENGINE] Response: {response}")
            return response
    except Exception as e:
        logging.error(f"[ADD ENGINE] Error: {e}")
        return f"Error: {e}"

def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='certs/server.crt', keyfile='certs/server.key')
    context.verify_mode = ssl.CERT_NONE  # Optional: use CERT_REQUIRED in production

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)

    with context.wrap_socket(sock, server_side=True) as ssock:
        logging.info(f"PEP ({ALLOWED_OPERATION}) is listening securely on {HOST}:{PORT}")
        while True:
            conn, addr = ssock.accept()
            with conn:
                data = conn.recv(2048)
                if not data:
                    continue
                try:
                    policy = json.loads(data.decode('utf-8'))
                    logging.info(f"Received policy: {policy}")

                    op = policy.get("operation", "").lower()
                    role = policy.get("role", "").lower()

                    if op != ALLOWED_OPERATION:
                        msg = f"Rejected: PEP only handles '{ALLOWED_OPERATION}'"
                        logging.warning(msg)
                        conn.send(msg.encode())
                        continue

                    if role not in ALLOWED_ROLES:
                        msg = f"Access Denied: role '{role}' not allowed to perform '{op}'"
                        logging.warning(msg)
                        conn.send(msg.encode())
                        continue

                    try:
                        num1 = float(policy.get("num1"))
                        num2 = float(policy.get("num2"))
                    except (ValueError, TypeError):
                        conn.send(b"Invalid numbers provided")
                        continue

                    result = forward_to_add_server(num1, num2)
                    conn.send(result.encode())

                except Exception as e:
                    logging.error(f"Error processing request: {e}")
                    conn.send(f"Error: {e}".encode())

if __name__ == '__main__':
    start_server()