import socket
import ssl
import mysql.connector
from mysql.connector import Error

# Define your database connection details
DB_CONFIG = {
    'host': 'localhost',
    'database': 'policy_db',
    'user': 'user',       # Use the dedicated user you created
    'password': 'password'  # Replace with your actual password
}

def get_role_for_ip(ip_address):
    """
    Query the database to retrieve the role for the given IP address.
    """
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            cursor = connection.cursor()
            query = "SELECT role FROM machine_role_mapping WHERE ip_address = %s"
            cursor.execute(query, (ip_address,))
            result = cursor.fetchone()
            return result[0] if result else "Unknown"
    except Error as e:
        print(f"Database error: {e}")
        return "Error"
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

def update_role_for_ip(ip_address, role):
    """
    Update or insert the role for the given IP address in the database.
    This function uses an INSERT ... ON DUPLICATE KEY UPDATE statement.
    Ensure that ip_address is a PRIMARY KEY or UNIQUE in your table.
    """
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            cursor = connection.cursor()
            query = """
            INSERT INTO machine_role_mapping (ip_address, role)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE role = %s
            """
            cursor.execute(query, (ip_address, role, role))
            connection.commit()
            return True
    except Error as e:
        print(f"Database error (update): {e}")
        return False
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

def start_server(host='0.0.0.0', port=9100):
    """
    Start a TCP server that listens for incoming SSL connections on the specified port.
    Expects the client to send either:
      - A plain IP address for a role lookup, or
      - A message in the form <IP>:<Role> to update the role mapping.
    """
    # Create a plain socket and bind it
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)  # Allow a backlog of 5 connections
    print(f"SSL Server listening on {host}:{port}")

    # Create an SSL context for server use
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Load your server certificate and private key.
    # Replace 'server.crt' and 'server.key' with the paths to your certificate and key files.
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"\nIncoming connection from {client_address[0]}")

            try:
                # Wrap the client socket to secure the connection
                ssl_socket = context.wrap_socket(client_socket, server_side=True)
                
                # Receive data from the client
                data = ssl_socket.recv(1024).decode('utf-8').strip()
                
                if not data:
                    # If no data is sent, default to client's source IP for lookup.
                    ip_address = client_address[0]
                    mode = "lookup"
                elif ":" in data:
                    # If the message contains a colon, assume the format is <IP>:<Role>
                    parts = data.split(":", 1)
                    if len(parts) == 2:
                        ip_address = parts[0].strip()
                        role = parts[1].strip()
                        mode = "update"
                    else:
                        # Fallback in case of a parsing issue.
                        ip_address = client_address[0]
                        mode = "lookup"
                else:
                    # Otherwise, treat the data as an IP address for lookup.
                    ip_address = data
                    mode = "lookup"

                if mode == "update":
                    print(f"Updating role for IP: {ip_address} to role: {role}")
                    success = update_role_for_ip(ip_address, role)
                    response = f"Update {'successful' if success else 'failed'} for {ip_address}\n"
                else:
                    print(f"Received IP for lookup: {ip_address}")
                    role = get_role_for_ip(ip_address)
                    print(f"IP {ip_address} is mapped to role: {role}")
                    response = f"{role}\n"

                # Send the response back to the client over the SSL socket
                ssl_socket.sendall(response.encode('utf-8'))

            except Exception as e:
                print(f"Error processing request from {client_address[0]}: {e}")
            finally:
                ssl_socket.close()
    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()
