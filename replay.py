import socket
import time

# Configuration: update these to point to your server.
SERVER_HOST = '35.225.178.159'  # Replace with your server's IP if needed.
SERVER_PORT = 9000              # Should match the server's listening port

def send_math_request(operation, num1, num2, timestamp):
    """
    Constructs a math request with a given timestamp in the format:
    math:<operation>:<num1>:<num2>:<timestamp>
    Sends the request to the server and returns the server's response.
    """
    message = f"math:{operation}:{num1}:{num2}:{timestamp}"
    print(f"[CLIENT] Sending: {message}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            client_socket.sendall(message.encode('utf-8'))
            response = client_socket.recv(1024).decode('utf-8').strip()
            print(f"[CLIENT] Received: {response}")
            return response
    except Exception as e:
        print(f"[CLIENT] Error: {e}")

def test_replay_attack():
    # Generate a fresh timestamp.
    current_timestamp = time.time()
    
    # Send a fresh math request.
    print("\n[TEST] Sending fresh math request...")
    send_math_request('add', 5, 10, current_timestamp)
    
    # Immediately send the same math request (simulate replay attack).
    print("\n[TEST] Sending replay of the same math request...")
    send_math_request('add', 5, 10, current_timestamp)
    
    # Optional: Simulate a stale request by waiting beyond the allowed window.
    stale_wait = 12  # Adjust if your ALLOWED_TIME_WINDOW is different (e.g., 10 seconds)
    print(f"\n[TEST] Waiting {stale_wait} seconds to simulate a stale request...")
    time.sleep(stale_wait)
    fresh_timestamp = time.time()
    print("\n[TEST] Sending new request with stale previous timestamp...")
    # Replay using the old (stale) timestamp.
    send_math_request('subtract', 20, 8, current_timestamp)
    
    # Also send a properly fresh request to confirm the server still works.
    print("\n[TEST] Sending new fresh math request with current timestamp...")
    send_math_request('subtract', 20, 8, fresh_timestamp)

if __name__ == "__main__":
    test_replay_attack()
