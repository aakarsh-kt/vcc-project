import ssl
import socket
import threading
import time
import subprocess

# --------------------------------------------------------------------------
# Configuration - replace these placeholders with your real service endpoints.
IAM_ROLES_HOST = '34.30.187.177'
IAM_ROLES_PORT = 9100

POLICY_ADMIN_HOST = '34.60.39.232'
POLICY_ADMIN_PORT = 8022

# Trust score weights and decision threshold
WEIGHTS = {
    'w1': 0.33,   # identity_score weight
    'w2': 0.33,   # device_integrity weight
    'w3': 0.33,   # threat_score weight
}
TRUST_THRESHOLD = 0.3

# DOS and Inactivity configuration
PACKETS_PER_SECOND_THRESHOLD = 2  # Max allowed packets per second
THROTTLE_DELAY_SECONDS = 5         # Delay when rate limit exceeded
INACTIVITY_TIMEOUT = 60            # Timeout in seconds when no data received

# Replay attack prevention configuration
ALLOWED_TIME_WINDOW = 1   # Allowed age (in seconds) for a timestamp in a request
# Global dictionary for storing processed timestamps (per client IP)
processed_requests = {}
processed_requests_lock = threading.Lock()

# --------------------------------------------------------------------------
# Functions for external service communication

def query_role_from_iam(ip_address):
    """
    Connect securely to the IAM roles VM, send the provided IP address,
    and return the role as a response.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((IAM_ROLES_HOST, IAM_ROLES_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname="IAM-ROLES") as ssock:
                ssock.sendall(ip_address.encode('utf-8'))
                response = ssock.recv(1024).decode('utf-8').strip()
                return response
    except Exception as e:
        return f"Error contacting IAM roles VM: {e}"

def update_role_in_iam(ip_address, role):
    """
    Updates the role for the given IP address on the IAM roles VM over SSL.
    The update is sent in the format: <IP>:<Role>:
    """
    message = f"{ip_address}:{role}:"
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((IAM_ROLES_HOST, IAM_ROLES_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname="IAM-ROLES") as ssock:
                ssock.sendall(message.encode('utf-8'))
                print(f"[IAM UPDATE] Sent update securely: {message}")
    except Exception as e:
        print(f"[IAM UPDATE] Error sending update: {e}")

def send_to_policy_admin(ip_address, role):
    """
    Inform the policy administrator of the client role using a secure SSL connection.
    """
    message = f"{ip_address}:{role}"
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((POLICY_ADMIN_HOST, POLICY_ADMIN_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname="SKY") as ssock:
                ssock.sendall(message.encode("utf-8"))
                print(f"[POLICY ADMIN] Sent securely: {message}")
    except Exception as e:
        print(f"[POLICY ADMIN] Secure send failed: {e}")

def process_math_operation_with_policy_admin(operation, num1, num2):
    """
    Packages the math operation request and sends it to the Policy Administrator.
    The expected message format is "<operation>:<num1>:<num2>".
    Waits for a response and returns the result.
    """
    message = f"{operation}:{num1}:{num2}"
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((POLICY_ADMIN_HOST, POLICY_ADMIN_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname="SKY") as ssock:
                ssock.sendall(message.encode("utf-8"))
                print(f"[POLICY ADMIN] Sent math operation securely: {message}")
                response = ssock.recv(1024).decode("utf-8").strip()
                print(f"[POLICY ADMIN RESPONSE] {response}")
                return response
    except Exception as e:
        print(f"[POLICY ADMIN] Secure math operation failed: {e}")
        return f"Error: {e}"
def process_math_operation_with_policy_admin(client_ip, operation, num1, num2):
    """
    Packages the math operation request and sends it to the Policy Administrator.
    The expected message format is "<operation>:<num1>:<num2>".
    Waits for a response and returns the result.
    """
    message = f"{client_ip}:{operation}:{num1}:{num2}"
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((POLICY_ADMIN_HOST, POLICY_ADMIN_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname="SKY") as ssock:
                ssock.sendall(message.encode("utf-8"))
                print(f"[POLICY ADMIN] Sent math operation securely: {message}")
                response = ssock.recv(1024).decode("utf-8").strip()
                print(f"[POLICY ADMIN RESPONSE] {response}")
                return response
    except Exception as e:
        print(f"[POLICY ADMIN] Secure math operation failed: {e}")
        return f"Error: {e}"
# --------------------------------------------------------------------------
# Identity Score Calculation Based on Role

def calculate_identity_score(role):
    """
    Assigns an identity score based on the provided role.
      - Returns 1 for admin
      - Returns  0 for regular user
      - Returns -1 for blocked
    """
    role = role.lower().strip()
    if role == 'admin':
        return 1.0
    elif role == 'user':
        return 0.0
    elif role == 'blocked':
        return -1.0
    else:
        # For any unrecognized role, you may choose a default value.
        return 0.0

# --------------------------------------------------------------------------
# Functions for trust score calculation

def calculate_threat_score(packet_count, packet_threshold=10):
    """
    Calculates a normalized threat score based on the number of packets received.
    If the packet count is below the threshold, returns a ratio,
    otherwise applies a penalty that increases sharply.
    """
    if packet_count <= packet_threshold:
        return packet_count / packet_threshold
    else:
        return min(1.0, (packet_count / packet_threshold) ** 1.5)

def calculate_trust_score(identity_score, device_integrity, threat_score, weights):
    """
    Calculates the overall trust score using a weighted sum.
    Assumes each metric is normalized (e.g., 0 to 1).
    """
    return (weights['w1'] * identity_score +
            weights['w2'] * device_integrity +
            weights['w3'] * threat_score)

def grant_access(client_socket, trust_score):
    message = f"Access Granted. Trust Score: {trust_score:.2f}\n"
    print("[Message]:", message)
    client_socket.sendall(message.encode('utf-8'))

def deny_or_limit_access(client_socket, trust_score):
    message = f"Access Denied or Limited. Trust Score: {trust_score:.2f}\n"
    client_socket.sendall(message.encode('utf-8'))
    client_socket.close()

# --------------------------------------------------------------------------
# Replay Attack Prevention Helper

def is_replay(client_ip, timestamp):
    """
    Checks if a given timestamp for a client has already been processed.
    Returns True if the timestamp is found in processed_requests, False otherwise.
    """
    with processed_requests_lock:
        if client_ip not in processed_requests:
            processed_requests[client_ip] = set()
        if timestamp in processed_requests[client_ip]:
            return True
        processed_requests[client_ip].add(timestamp)
    return False

# --------------------------------------------------------------------------
# Continuous ping function using a dedicated thread

def ping_client(ip_address, stop_event):
    """
    Continuously ping the client identified by ip_address until stop_event is set.
    Logs whether the client is reachable every 10 seconds.
    """
    while not stop_event.is_set():
        try:
            result = subprocess.run(
                ["ping", "-c", "1", ip_address],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                print(f"[PING] {ip_address} is reachable.")
            else:
                print(f"[PING] {ip_address} is unreachable.")
        except Exception as e:
            print(f"[PING] Error pinging {ip_address}: {e}")
        time.sleep(10)

# --------------------------------------------------------------------------
# Device Integrity Calculation
def calculate_device_integrity():
    """
    Calculates a basic device integrity score by running simple system checks.
    Returns a normalized value between 0 (poor integrity) and 1 (high integrity).

    For demonstration purposes, this function:
      - Checks the kernel version, and assigns a higher score if it starts with '5.'.
      - Checks for the existence of a known secure file (for example, '/etc/secure.conf').
    
    In a real-world scenario, you would replace these checks with robust attestation,
    TPM-based measurements, or agent-based reporting.
    """
    score = 0.0

    try:
        # Check the kernel version
        proc = subprocess.run(["uname", "-r"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        kernel_version = proc.stdout.strip()
        print(f"[DEVICE INTEGRITY] Kernel version: {kernel_version}")
        if kernel_version.startswith("5."):
            score += 0.5  # Weight: 50% of integrity score from kernel version
        else:
            score += 0.3

        # Check for the existence of a secure configuration file as a proxy for system hardening.
        secure_conf_path = '/etc/secure.conf'
        try:
            with open(secure_conf_path, 'r') as f:
                data = f.read().strip()
            print(f"[DEVICE INTEGRITY] Found secure configuration file: {secure_conf_path}")
            # You might check the contents or checksum of this file in a real implementation.
            score += 0.5  # Weight: 50% from secure configuration file check
        except FileNotFoundError:
            print(f"[DEVICE INTEGRITY] Secure configuration file not found: {secure_conf_path}")
            score += 0.0

    except Exception as e:
        print(f"[DEVICE INTEGRITY] Error during integrity check: {e}")
        score = 0.5  # Default to a mid-range score on error

    # Normalize score to a maximum of 1.0
    normalized_score = min(1.0, score)
    print(f"[DEVICE INTEGRITY] Calculated integrity score: {normalized_score:.2f}")
    return normalized_score

# --------------------------------------------------------------------------
# Client handler which implements both trust score evaluation and math resources.

def handle_client(client_socket, client_address):
    """
    Handles an individual client connection.
    - Retrieves the client IP.
    - Queries IAM roles VM for the role.
    - If the role is unknown, prompts the new user to select one.
    - Informs the Policy Administrator.
    - Processes math requests and trust score evaluations.
    """
    client_ip = client_address[0]
    print(f"\n[CONNECT] New connection from {client_ip}")

    client_socket.settimeout(INACTIVITY_TIMEOUT)
    packet_timestamps = []

    # Step 1: Get role from the IAM roles service.
    role = query_role_from_iam(client_ip)
    print(f"[ROLE] Role for {client_ip} (from IAM roles VM): {role}")

    if role.lower() == "unknown" or role == "":
        prompt_message = ("[SYSTEM] Your role is unknown. "
                          "Please select your role from the following options: "
                          "admin, user, blocked\n")
        try:
            client_socket.sendall(prompt_message.encode('utf-8'))
            new_role = client_socket.recv(1024).decode('utf-8').strip().lower()
            if new_role not in ['admin', 'user', 'blocked']:
                error_message = "[SYSTEM] Invalid selection received. Defaulting to 'user' role.\n"
                client_socket.sendall(error_message.encode('utf-8'))
                new_role = 'user'
            print(f"[ROLE SELECTION] {client_ip} selected role: {new_role}")
            update_role_in_iam(client_ip, new_role)
            role = new_role
        except Exception as e:
            print(f"[ROLE SELECTION] Error during role selection for {client_ip}: {e}")
            role = "user"

    # Step 2: Inform the Policy Administrator.
    send_to_policy_admin(client_ip, role)

    # (Optional) Start continuous ping thread.
    stop_ping_event = threading.Event()
    # ping_thread = threading.Thread(target=ping_client, args=(client_ip, stop_ping_event))
    # ping_thread.daemon = True; ping_thread.start()

    # Simulated metrics for demonstration.
    identity_score = calculate_identity_score(role)
    # Use the new function to calculate device integrity.
    device_integrity = calculate_device_integrity()
    print(f"[IDENTITY SCORE] {identity_score}")
    print(f"[INTEGRITY SCORE] {device_integrity}")
    packet_count = 0
    threat_score = calculate_threat_score(packet_count, packet_threshold=10)
    print(f"[THREAT SCORE] {threat_score}")
    trust_score = calculate_trust_score(
         identity_score,
         device_integrity,
         threat_score,
         WEIGHTS
    )
    print(f"[TRUST SCORE] {trust_score}")
    access_granted = False

    try:
        while True:
            try:
                data = client_socket.recv(1024)
            except socket.timeout:
                print(f"[TIMEOUT] No data received from {client_ip} for {INACTIVITY_TIMEOUT} seconds. Disconnecting.")
                break

            if not data:
                print(f"[DISCONNECT] {client_ip} closed the connection.")
                break

            current_time = time.time()
            packet_timestamps.append(current_time)
            packet_timestamps = [ts for ts in packet_timestamps if current_time - ts <= 1]

            if len(packet_timestamps) > PACKETS_PER_SECOND_THRESHOLD:
                print(f"[DOS] Rate limit exceeded for {client_ip} with {len(packet_timestamps)} packets/sec. Throttling...")
                time.sleep(THROTTLE_DELAY_SECONDS)
                continue

            message = data.decode('utf-8').strip()
            print(f"[MESSAGE] Received from {client_ip}: {message}")

            if message.startswith('math:'):
                parts = message.split(':')
                if len(parts) == 5:
                    _, operation, op1, op2, msg_timestamp = parts
                    try:
                        msg_time = float(msg_timestamp)
                    except ValueError:
                        client_socket.sendall(b"Invalid timestamp provided.\n")
                        continue

                    now = time.time()
                    if abs(now - msg_time) > ALLOWED_TIME_WINDOW:
                        client_socket.sendall(b"Stale request detected. Possible replay attack.\n")
                        continue

                    if is_replay(client_ip, msg_timestamp):
                        client_socket.sendall(b"Replay detected. Request rejected.\n")
                        continue

                    try:
                        num1 = float(op1)
                        num2 = float(op2)
                        if operation.lower() not in ['add', 'sub']:
                            client_socket.sendall(b"Invalid operation. Only 'add' and 'sub' are allowed.\n")
                            continue
                        result = process_math_operation_with_policy_admin(client_ip, operation.lower(), num1, num2)
                        client_socket.sendall(f"Result: {result}\n".encode('utf-8'))
                    except ValueError:
                        client_socket.sendall(b"Invalid numbers provided. Please send numeric values.\n")
                else:
                    client_socket.sendall(b"Invalid math request format. Use math:<operation>:<num1>:<num2>:<timestamp>\n")
                continue

            packet_count += 1
            threat_score = calculate_threat_score(packet_count, packet_threshold=10)
            trust_score = calculate_trust_score(
                identity_score,
                device_integrity,
                session_context,
                threat_score,
                WEIGHTS
            )

            print(f"[TRUST] {client_ip}: Packet Count: {packet_count}, Threat Score: {threat_score:.2f}, Total Trust Score: {trust_score:.2f}")

            if trust_score >= TRUST_THRESHOLD and not access_granted:
                access_granted = True
                grant_access(client_socket, trust_score)
            elif trust_score < TRUST_THRESHOLD and not access_granted:
                print(f"[ACCESS] Denying or limiting access to {client_ip}.")
                deny_or_limit_access(client_socket, trust_score)
                break

            client_socket.sendall(data)

    except Exception as e:
        print(f"[ERROR] Connection error with {client_ip}: {e}")
    finally:
        stop_ping_event.set()
        client_socket.close()
        print(f"[CLEANUP] Closed connection with {client_ip}")


# --------------------------------------------------------------------------
# Main server loop: listens for incoming connections and spawns a thread per connection.

def start_server(host='0.0.0.0', port=9000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[SERVER] Listening on {host}:{port}")
    
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Server shutting down (KeyboardInterrupt).")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()
