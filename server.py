import socket
import threading
import logging

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("server_chat.log"),
        logging.StreamHandler()
    ]
)

HOST = '127.0.0.1'
PORT = 55555

clients = []
clients_lock = threading.Lock()

def broadcast(message: bytes, sender_socket: socket.socket):
    """Broadcasts encrypted bytes to all clients except the sender."""
    with clients_lock:
        for client in clients:
            if client != sender_socket:
                try:
                    # Prefix message length (4 bytes) to handle TCP streaming splits/merges
                    client.sendall(len(message).to_bytes(4, byteorder='big') + message)
                except Exception as e:
                    logging.error(f"Error broadcasting to a client: {e}")
                    client.close()
                    if client in clients:
                        clients.remove(client)

def handle_client(client_socket: socket.socket, client_address: tuple):
    """Handles the lifecycle of a single connected client."""
    logging.info(f"New connection established from {client_address}")
    with clients_lock:
        clients.append(client_socket)

    while True:
        try:
            # Read the 4-byte length prefix
            len_bytes = client_socket.recv(4)
            if not len_bytes:
                break
            
            message_len = int.from_bytes(len_bytes, byteorder='big')
            
            # Read the exact size of the payload
            data = b''
            while len(data) < message_len:
                packet = client_socket.recv(message_len - len(data))
                if not packet:
                    break
                data += packet
                
            if data:
                logging.info(f"Received encrypted payload from {client_address} ({len(data)} bytes). Broadcasting...")
                broadcast(data, client_socket)
                
        except ConnectionResetError:
            break
        except Exception as e:
            logging.error(f"Error handling client {client_address}: {e}")
            break

    # Cleanup on disconnect
    with clients_lock:
        if client_socket in clients:
            clients.remove(client_socket)
    client_socket.close()
    logging.info(f"Connection closed with {client_address}")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    logging.info(f"Server is listening on {HOST}:{PORT}...")

    try:
        while True:
            client_socket, client_address = server.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()