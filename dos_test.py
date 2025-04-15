import socket
import time

# Configuration
SERVER_HOST = '35.225.178.159'  # Update if needed, e.g., your server's IP
SERVER_PORT = 9000         # Must match the port in your server script

def send_high_rate_packets(rate, duration):
    """
    Connects to the server and sends packets at a given rate (packets per second)
    for the specified duration (in seconds). This simulates a DOS attack.
    """
    try:
        print(f"[CLIENT] Creating socket...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[CLIENT] Attempting to connect to {SERVER_HOST}:{SERVER_PORT}")
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print(f"[CLIENT] Connected to server {SERVER_HOST}:{SERVER_PORT} for high-rate packet test.")
        
        # Use a simple message repeatedly.
        message = "dos_test_packet"
        start_time = time.time()
        packet_count = 0

        while time.time() - start_time < duration:
            client_socket.sendall(message.encode('utf-8'))
            packet_count += 1
            # Sleep to maintain the desired sending rate.
            time.sleep(1.0 / rate)
        
        print(f"[CLIENT] Sent {packet_count} packets in {duration} seconds at a rate of {rate} packets/sec.")
        
        # Optionally, wait for the server's echo (if implemented) to see responses.
        try:
            response = client_socket.recv(1024)
            if response:
                print("[CLIENT] Received response:", response.decode('utf-8').strip())
        except Exception as e:
            print("[CLIENT] No response received (likely due to throttling):", e)

    except Exception as error:
        print(f"[CLIENT] Error during high rate test: {error}")
    finally:
        client_socket.close()
        print("[CLIENT] Connection closed after high-rate test.\n")


def test_inactivity_timeout(timeout_duration):
    """
    Connects to the server and then idles (sleeps) for longer than the server's inactivity
    timeout. This tests whether the server correctly disconnects idle clients.
    """
    try:
        print(f"[CLIENT] Creating socket for inactivity test...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[CLIENT] Attempting to connect to {SERVER_HOST}:{SERVER_PORT} for inactivity test.")
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print(f"[CLIENT] Connected to server {SERVER_HOST}:{SERVER_PORT} for inactivity test.")
        
        # Wait for longer than the server's inactivity timeout.
        print(f"[CLIENT] Idling for {timeout_duration} seconds to trigger inactivity timeout...")
        time.sleep(timeout_duration)

        # Try reading data after inactivity period.
        try:
            response = client_socket.recv(1024)
            if response:
                print("[CLIENT] Received response after inactivity (unexpected):", response.decode('utf-8').strip())
            else:
                print("[CLIENT] No data received; connection may have been closed by server as expected.")
        except Exception as e:
            print("[CLIENT] Expected exception occurred after inactivity (server closed connection):", e)
    except Exception as error:
        print(f"[CLIENT] Error during inactivity test: {error}")
    finally:
        client_socket.close()
        print("[CLIENT] Connection closed after inactivity test.")


def main():
    # Test 1: High packet rate to simulate DOS attack.
    # Using a rate of 20 packets per second for 5 seconds.
    send_high_rate_packets(rate=20, duration=5)

    # Test 2: Inactivity test.
    # The server is set to disconnect after 60 seconds of inactivity.
    test_inactivity_timeout(timeout_duration=70)  # 70 seconds to ensure timeout is reached.

if __name__ == '__main__':
    main()
  
