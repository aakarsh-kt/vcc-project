#!/usr/bin/env python3
import socket
import ssl
import threading
import logging
import signal
import sys
import json
from pep_client import send_to_pep
from db_utils import store_role, get_role

# Server config
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 8022
CERTFILE = 'server.crt'
KEYFILE = 'server.key'

# In-memory map to store IP → role
ip_to_role_map = {}

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("connections.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

def handle_client(conn, addr):
    client_ip, client_port = addr
    logging.info(f"Connection from {client_ip}:{client_port}")
    try:
        conn.settimeout(120)
        data = b""
        while True:
            chunk = conn.recv(1024)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 1024:
                break  # End of message

        msg = data.decode("utf-8", errors="replace").strip()
        logging.info(f"Raw payload: '{msg}'")

        parts = msg.split(":")
        if len(parts) == 2:
            # Role update message
            payload_ip = parts[0].strip()
            role = parts[1].strip().lower()
            store_role(payload_ip, role)
            logging.info(f"Role update request - IP: {payload_ip}, Role: {role}")

            policy = {
                "user": payload_ip,
                "role": role
            }
            pep_response = send_to_pep(policy)
            logging.info(f"PEP Response: {pep_response}")
            try:
                conn.sendall(pep_response.encode())
            except ssl.SSLEOFError:
                logging.warning(f"Client disconnected before receiving response")

        elif len(parts) == 4:
            # Math operation message

            operation = parts[1].strip().lower()
            ipAdd = parts[0].strip().lower()
            num1 = parts[2].strip()
            num2 = parts[3].strip()
            role = get_role(ipAdd) or "unknown"
            print(f"Role :{role}")
            logging.info(f"Math request from {client_ip} with role '{role}'")

            policy = {
                "operation": operation,
                "num1": num1,
                "num2": num2,
                "role": role
            }

            pep_response = send_to_pep(policy)
            logging.info(f"PEP Response: {pep_response}")
            conn.sendall(pep_response.encode())

        else:
            msg = "Invalid format. Use either <ip>:<role> or <operation>:<num1>:<num2>"
            logging.warning(msg)
            conn.sendall(msg.encode())

    except Exception as e:
        logging.error(f"Error handling client {client_ip}:{client_port}: {e}")
        conn.sendall(f"Error: {e}".encode())
    finally:
        conn.close()
        logging.info(f"Connection closed with {client_ip}:{client_port}")

def start_secure_server(host=LISTEN_HOST, port=LISTEN_PORT):
    base_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    base_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    base_socket.bind((host, port))
    base_socket.listen(5)
    logging.info(f"Listening on {host}:{port}")

    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
        secure_socket = context.wrap_socket(base_socket, server_side=True)
    except Exception as e:
        logging.error(f"Failed to load SSL certificate: {e}")
        sys.exit(1)

    def shutdown(signum, frame):
        logging.info("Shutting down server.")
        secure_socket.close()
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)

    while True:
        try:
            conn, addr = secure_socket.accept()
        except ssl.SSLError as e:
            logging.warning(f"SSL error during accept: {e}")
            continue
        except Exception as e:
            logging.error(f"Error accepting connection: {e}")
            continue

        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.daemon = True
        client_thread.start()

if __name__ == '__main__':
    start_secure_server()