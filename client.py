import socket
import threading
import sys
from crypto_utils import derive_key, encrypt_message, decrypt_message

HOST = '127.0.0.1'
PORT = 55555

def receive_messages(client_socket: socket.socket, key: bytes):
    """Continuously receives and decrypts incoming messages from the server."""
    while True:
        try:
            # Read the 4-byte message length header
            len_bytes = client_socket.recv(4)
            if not len_bytes:
                print("\n[Disconnected from server.]")
                sys.exit()
                
            message_len = int.from_bytes(len_bytes, byteorder='big')
            
            # Read the complete encrypted payload
            data = b''
            while len(data) < message_len:
                packet = client_socket.recv(message_len - len(data))
                if not packet:
                    break
                data += packet

            # Decrypt the payload locally using the shared key
            decrypted_msg = decrypt_message(data, key)
            print(f"\n{decrypted_msg}")
            print("You: ", end="", flush=True)

        except Exception as e:
            print(f"\n[Error/Decryption failure]: {e}")
            client_socket.close()
            sys.exit()

def start_client():
    # 1. Handle Pre-Shared Key Setup
    password = input("Enter the pre-shared secret room password: ").strip()
    if not password:
        print("Password cannot be empty.")
        return
    
    shared_key = derive_key(password)
    username = input("Enter your username: ").strip()

    # 2. Connect to Server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((HOST, PORT))
        print(f"[Connected securely to chat server at {HOST}:{PORT}]")
    except Exception as e:
        print(f"Failed to connect: {e}")
        return

    # 3. Start background thread to listen for incoming data
    receive_thread = threading.Thread(target=receive_messages, args=(client, shared_key))
    receive_thread.daemon = True
    receive_thread.start()

    # 4. Main loop for sending messages
    try:
        while True:
            msg = input("You: ")
            if msg.lower() == '/quit':
                break
            if not msg.strip():
                continue

            formatted_msg = f"{username}: {msg}"
            
            # Encrypt locally using AES-GCM
            encrypted_payload = encrypt_message(formatted_msg, shared_key)
            
            # Send payload length header followed by the actual data
            payload_len = len(encrypted_payload).to_bytes(4, byteorder='big')
            client.sendall(payload_len + encrypted_payload)
            
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        client.close()

if __name__ == "__main__":
    start_client()