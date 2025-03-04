import socket
import struct
import uuid
from termcolor import colored
# from utils import (
#     load_public_key,
#     generate_dh_private_key,
#     get_public_key_bytes,
#     derive_shared_key,
#     derive_des_keys,
#     double_des_encrypt,
#     double_des_decrypt,
#     generate_hmac,
#     verify_hmac,
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

# Client program start


IP = socket.gethostbyname(socket.gethostname())
PORT = 5566
ADDR = (IP, PORT)
DISCONNECT_MSG = 50  # Opcode for disconnect


def send_data(conn, opcode, data):

    try:
        conn.sendall(struct.pack("!I", opcode) + struct.pack("!I", len(data)) + data)
        # if opcode == 30:
        #     print(colored(f"[STATUS] Sent number {num_count + 1} successfully.", "cyan"))
    except socket.error as e:
        print(colored(f"[ERROR] Failed to send data: {e}", "red"))
    except Exception as e:
        print(colored(f"[ERROR] An unexpected error occurred while sending data: {e}", "red"))



def recv_data(conn):
    try:
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
    except socket.error as e:
        print(colored(f"[ERROR] Socket error: {e}", "red"))
        return None, None


def main():
    # client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # client.connect(ADDR)
    # print(colored(f"[CONNECTED] Client connected to server at {IP}:{PORT}", "green"))

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(ADDR)
        print(colored(f"[CONNECTED] Client connected to server at {IP}:{PORT}", "green"))
    except socket.error as e:
        print(colored(f"[ERROR] Failed to connect to server at {IP}:{PORT}: {e}", "red"))
    except Exception as e:
        print(colored(f"[ERROR] An unexpected error occurred: {e}", "red"))

    client_uuid = uuid.uuid4()
    client_id_int = int(client_uuid)
    print(colored(f"[CLIENT ID] UUID: {client_uuid}, Integer: {client_id_int}", "cyan"))

    # Step 1: Receive the server's public key
    opcode, server_public_key_bytes = recv_data(client)
    if opcode != 10 or not server_public_key_bytes:
        print(colored("[ERROR] Failed to receive server's public key.", "red"))
        client.close()
        return
    print(colored("[STATUS] Received server's public key.", "cyan"))

    # Step 2: Load the server's public key
    server_public_key = load_public_key(server_public_key_bytes)
    print(colored("[STATUS] Loaded server's public key.", "cyan"))

    # Step 3: Generate DH private key and shared keys
    param_numbers = server_public_key.public_numbers().parameter_numbers
    client_dh_parameters = param_numbers.parameters()
    client_private_key = client_dh_parameters.generate_private_key()
    client_public_key_bytes = get_public_key_bytes(client_private_key.public_key())
    send_data(client, 10, client_public_key_bytes)
    print(colored("[STATUS] Sent client's public key to server.", "cyan"))

    shared_key = derive_shared_key(client_private_key, server_public_key)
    key1, key2 = derive_des_keys(shared_key)
    print(colored("[STATUS][10] Shared keys derived successfully.", "cyan"))

    # Step 4: Receive session token from the server
    opcode, encrypted_token = recv_data(client)
    if opcode != 20 or not encrypted_token:
        print(colored("[ERROR] Failed to receive session token.", "red"))
        client.close()
        return
    session_token = double_des_decrypt(encrypted_token, key1, key1)
    print(colored(f"[STATUS][20] Received session token: {session_token.hex()}", "cyan"))


    num_count = 0
    connected = True

    while connected :
        print(colored("\nAvailable Opcodes:", "cyan"))
        print(colored("  30 - Send encrypted data", "yellow"))
        print(colored("  50 - Disconnect", "yellow"))

        try:
            opcode = int(input(colored("Enter the opcode (30 to send data, 50 to disconnect): ", "yellow")))
            if opcode not in [30, 50]:
                print(colored("[ERROR] Invalid opcode. Please enter 30 or 50.", "red"))
                continue

            if opcode == 50:
                print(colored("[STATUS] Disconnection request sent.", "yellow"))
                send_data(client, DISCONNECT_MSG, b"")
                connected = False
                break

            integer_to_send = int(input(colored(f"Enter an integer: ", "yellow")))
        except ValueError:
            print(colored("[ERROR] Invalid input. Please enter valid opcode and integer.", "red"))
            continue

        # Prepare data: number + client ID
        integer_bytes = integer_to_send.to_bytes(8, byteorder="big")
        client_id_bytes = client_id_int.to_bytes(16, byteorder="big")
        message = integer_bytes + client_id_bytes

        # Encrypt the message and append session token
        encrypted_message = double_des_encrypt(message, key1, key2)
        encrypted_message_with_token = encrypted_message + session_token

        # Generate HMAC
        hmac_code = generate_hmac(key2, encrypted_message_with_token)

        # Send encrypted message with HMAC
        data_to_send = encrypted_message_with_token + hmac_code
        send_data(client, opcode, data_to_send)
        
        # print(colored(f"[STATUS] message number {num_count + 1} sent.", "cyan"))

        num_count += 1

        # Receive acknowledgment from the server
        opcode, response_data = recv_data(client)
        if opcode == 30:  # Server acknowledges the received number
            # print(colored(response_data.decode("utf-8"), "cyan"))
            print(colored(f"[STATUS] message number {num_count} sent.", "cyan"))
        
        # Step 6: Receive and verify the aggregated result or timeout message
        opcode, response_data = recv_data(client)
        if opcode is None and response_data is None:
            print(colored("[INFO][50] Server closed the connection (connection time out).", "red"))
            client.close()
            return

        if opcode == DISCONNECT_MSG:
            print(colored(response_data.decode("utf-8"), "red"))
            client.close()
            return

        if opcode == 40 and response_data:
            # Decrypt the aggregated result or the first number
            encrypted_result = response_data[:-32]
            received_hmac = response_data[-32:]

            # Descryting the send data
            decrypted_result = double_des_decrypt(encrypted_result, key1, key2)

            # Verify the HMAC
            if not verify_hmac(key2, encrypted_result, received_hmac):
                print(colored("[ERROR] Invalid HMAC for the result.", "red"))
                client.close()
                return

            print(colored(f"[SERVER RESULT] Result: {decrypted_result.decode('utf-8')}", "green"))



    send_data(client, DISCONNECT_MSG, b"")
    client.close()
    print(colored("[STATUS] Client disconnected.", "yellow"))


if __name__ == "__main__":
    main()