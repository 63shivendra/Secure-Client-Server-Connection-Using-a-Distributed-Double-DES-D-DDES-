import socket
import threading
import struct
import time
from termcolor import colored
# from utils import (
#     generate_dh_parameters,
#     generate_dh_private_key,
#     get_public_key_bytes,
#     load_public_key,
#     derive_shared_key,
#     derive_des_keys,
#     double_des_encrypt,
#     double_des_decrypt,
#     generate_hmac,
#     verify_hmac,
#     generate_session_token,
# )



import hmac
import os
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from Crypto.Cipher import DES

BLOCK_SIZE = 8  # DES block size is 8 bytes


def generate_dh_parameters(key_size=2048):
    return dh.generate_parameters(generator=2, key_size=key_size)


def generate_dh_private_key(parameters):
    return parameters.generate_private_key()


def get_public_key_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)


def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"handshake data",
    ).derive(shared_secret)


def derive_des_keys(shared_key):
    if len(shared_key) < 16:
        raise ValueError("Shared key must be at least 16 bytes.")
    return shared_key[:8], shared_key[8:16]


def pad(data):
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len]) * padding_len


def unpad(data):
    return data[:-data[-1]]


def double_des_encrypt(plaintext, key1, key2):
    plaintext = pad(plaintext)
    cipher1 = DES.new(key1, DES.MODE_ECB)
    intermediate = cipher1.encrypt(plaintext)
    cipher2 = DES.new(key2, DES.MODE_ECB)
    return cipher2.encrypt(intermediate)


def double_des_decrypt(ciphertext, key1, key2):
    cipher2 = DES.new(key2, DES.MODE_ECB)
    intermediate = cipher2.decrypt(ciphertext)
    cipher1 = DES.new(key1, DES.MODE_ECB)
    try:
        return unpad(cipher1.decrypt(intermediate))
    except ValueError:
        raise ValueError("Decrypted data is corrupted or tampered with.")


def generate_hmac(key, message):
    return hmac.new(key, message, sha256).digest()


def verify_hmac(key, message, received_hmac):
    computed_hmac = generate_hmac(key, message)
    return hmac.compare_digest(computed_hmac, received_hmac)


def generate_session_token():
    return os.urandom(16)


# Server program start




IP = socket.gethostbyname(socket.gethostname())
PORT = 5566
ADDR = (IP, PORT)
DISCONNECT_MSG = 50  # Opcode for disconnect
TIMEOUT_DURATION = 60  

aggregated_data = {}
client_keys = {}
client_timers = {}
connections = []  # List to track all active client connections

stop_event = threading.Event()

def send_data(conn, opcode, data):
    conn.sendall(struct.pack("!I", opcode) + struct.pack("!I", len(data)) + data)

def recv_data(conn):
    raw_opcode = conn.recv(4)
    if not raw_opcode:
        return None, None
    opcode = struct.unpack("!I", raw_opcode)[0]
    raw_len = conn.recv(4)
    if not raw_len:
        return opcode, None
    msg_len = struct.unpack("!I", raw_len)[0]
    data = b""
    while len(data) < msg_len:
        packet = conn.recv(msg_len - len(data))
        if not packet:
            return opcode, None
        data += packet
    return opcode, data

def broadcast_disconnect(reason: bytes):
    """
    Send DISCONNECT_MSG (50) to all connected clients, close their sockets, 
    and clear the list of active connections.
    """
    print(colored(f"[BROADCAST] Ending session for ALL participants. Reason: {reason.decode('utf-8', 'ignore')}", "red"))
    
    for (c, address) in connections:
        try:
            send_data(c, DISCONNECT_MSG, reason)
            c.close()
        except:
            pass
    connections.clear()

def handle_client(conn, addr):
    global client_timers, connections
    print()
    print(colored(f"[NEW CONNECTION] {addr} connected.", "green"))

    # Add client connection to the list
    connections.append((conn, addr))

    try:
        # Step 1: Diffie-Hellman Key Exchange (Opcode: 10)
        dh_params = generate_dh_parameters()
        server_private_key = generate_dh_private_key(dh_params)
        server_public_key_bytes = get_public_key_bytes(server_private_key.public_key())
        send_data(conn, 10, server_public_key_bytes)

        opcode, client_public_key_bytes = recv_data(conn)
        print(colored(f"[10] KEY VERIFICATION for client {addr}", "cyan"))
        if opcode != 10 or not client_public_key_bytes:
            raise ValueError("Invalid or missing public key from client.")

        client_public_key = load_public_key(client_public_key_bytes)
        shared_key = derive_shared_key(server_private_key, client_public_key)
        key1, key2 = derive_des_keys(shared_key)

        # Session Token
        session_token = generate_session_token()
        encrypted_token = double_des_encrypt(session_token, key1, key1)
        send_data(conn, 20, encrypted_token)
        print(colored(f"[20] Shared SESSION KEY to client {addr}", "cyan"))

        client_id = addr[1]
        aggregated_data[client_id] = 0
        client_keys[client_id] = {"key1": key1, "key2": key2}
        client_timers[client_id] = time.time()

        for i in range(1000000):
            while True:

                elapsed = time.time() - client_timers[client_id]
                remaining = TIMEOUT_DURATION - elapsed
                if stop_event.is_set():
                    return

                if remaining <= 0:
                    if i == 0:
                        print()
                        print(colored(f"[TIMEOUT] Client {addr} provided no data. Closing connection.", "red"))
                        send_data(conn, DISCONNECT_MSG, b"Timeout: No data provided.")
                        conn.close()
                        return
                    else:
                        print()
                        print(colored(f"[TIMEOUT] Client {addr}: Returning number.", "yellow"))
                        result_message = str(aggregated_data[client_id]).encode("utf-8")
                        encrypted_result = double_des_encrypt(result_message, key1, key2)
                        result_hmac = generate_hmac(key2, encrypted_result)
                        send_data(conn, 40, encrypted_result + result_hmac)
                        print(colored(f"[40] Sent ENC AGGR RESULT to client {addr}", "cyan"))
                        conn.close()
                        return

                print(f"\r[TIMER] Client {addr}: {int(remaining)} seconds remaining", end="")

                # Wait for data
                conn.settimeout(1)
                try:
                    opcode, enc_data = recv_data(conn)
                    
                    if opcode == 30 and enc_data:
                        print()
                        print(colored(f"[STATUS] Message received from client {addr}", "cyan"))
                        break

                    if opcode == DISCONNECT_MSG:
                        print(colored(f"\n[CLIENT DISCONNECT][50] {addr} wants to end all sessions.", "red"))
                        
                        # Disconnect all clients
                        broadcast_disconnect(b"Client requested session end for all.")
                        return

                except socket.timeout:
                    continue
                except (ConnectionResetError, BrokenPipeError):
                    print(colored(f"[DISCONNECT][50] Client {addr} has disconnected. Closing connection.", "red"))
                    conn.close()
                    return
                except Exception as e:
                    print(colored(f"[ERROR] Unexpected error: {e}. Closing connection.", "red"))
                    conn.close()
                    return

            # Process received data
            print()
            encrypted_message_with_token = enc_data[:-32]
            received_hmac = enc_data[-32:]

            encrypted_message = encrypted_message_with_token[:-len(session_token)]
            received_session_token = encrypted_message_with_token[-len(session_token):]

            # Session Token Validation
            if received_session_token != session_token:
                print(colored("[ERROR] Session token verification failed.", "red"))
                send_data(conn, DISCONNECT_MSG, b"Error: Invalid session token. Connection terminated.")
                conn.close()
                return
            print(colored(f"[STATUS] SESSION KEY verified for client {addr}", "cyan"))

            # HMAC Verification
            if not verify_hmac(key2, encrypted_message_with_token, received_hmac):
                print(colored("[ERROR] HMAC verification failed.", "red"))
                send_data(conn, DISCONNECT_MSG, b"Error: Invalid HMAC. Connection terminated.")
                conn.close()
                return
            print(colored("[HMAC VERIFIED SUCCESSFULLY]", "green"))

            # Double DES Decryption
            try:
                decrypted_message = double_des_decrypt(encrypted_message, key1, key2)
            except ValueError:
                print(colored("[ERROR] Data tampering detected during decryption.", "red"))
                send_data(conn, 30, b"Warning: Data tampering detected. Message discarded.")
                continue  

            print(colored(f"[STATUS] Decrypted client {addr} Message", "cyan"))

            # Aggregate the data
            integer_value = int.from_bytes(decrypted_message[:8], byteorder="big")
            aggregated_data[client_id] += integer_value
            client_timers[client_id] = time.time()

            send_data(conn, 30, f"Server Received number".encode("utf-8"))
            print(colored(f"[STATUS] Client {addr}: Received {integer_value}", "cyan"))

            result_message = str(aggregated_data[client_id]).encode("utf-8")
            encrypted_result = double_des_encrypt(result_message, key1, key2)
            result_hmac = generate_hmac(key2, encrypted_result)
            send_data(conn, 40, encrypted_result + result_hmac)
            print(colored(f"[40] Sent ENC AGGR RESULT to client {addr}", "cyan"))

    except Exception as e:
        print(colored(f"[ERROR] {addr}: {e}", "red"))
    finally:
        conn.close()
        print(colored(f"[DISCONNECTED][50] {addr} connection closed.", "yellow"))

def server_loop():
    print(colored("[SERVER STARTING] Server is starting...", "yellow"))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    print(colored(f"[SERVER LISTENING] Server listening on {IP}:{PORT}", "green"))

    while not stop_event.is_set():
        try:
            server.settimeout(1)
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
        except socket.timeout:
            continue 
        except Exception as e:
            print(colored(f"[ERROR] {e}", "red"))

    server.close()


def main():
    server_thread = threading.Thread(target=server_loop)
    server_thread.start()

    
    while True:
        user_input = input(colored("Enter 'exit' to stop the server: ", "yellow")).strip().lower()
        
        if user_input == "exit":
            stop_event.set()
            break

    server_thread.join()
    print(colored("[SERVER EXITED][50] Server has shut down.", "green"))



if __name__ == "__main__":
    main()