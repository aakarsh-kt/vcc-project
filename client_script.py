import socket
from datetime import datetime

def run_client(server_host='35.225.178.159', server_port=9000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((server_host, server_port))
        print("[CONNECTED] Type your operation (e.g., ADD:2:3 or SUB:10:5). Type EXIT to quit.\n")

        while True:
            msg = input(">> ").strip()
            if msg.upper() == "EXIT":
                break

            # Simple client-side validation to prevent scripts
            if any(x in msg.lower() for x in ['import', 'os', 'eval', 'exec', '__']):
                print("[WARNING] Script-like input blocked for security.")
                continue

            try:
                # Expecting input like ADD:2:3
                parts = msg.split(":")
                if len(parts) != 3:
                    print("[ERROR] Invalid format. Use OPERATION:NUM1:NUM2")
                    continue

                op, num1, num2 = parts[0].lower(), parts[1], parts[2]
                timestamp = str(int(datetime.utcnow().timestamp()))
                full_msg = f"math:{op}:{num1}:{num2}:{timestamp}"
                client_socket.sendall(full_msg.encode('utf-8'))

                response = client_socket.recv(1024).decode('utf-8')
                print("[RESPONSE]:", response)
            except Exception as e:
                print(f"[ERROR] {e}")

if __name__ == "__main__":
    run_client()
