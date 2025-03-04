# Secure Client-Server Connection Using a Distributed Double DES (D-DDES)
**Shivendra Pratap Singh** - (2024202022)

## Project folder structure

3_lab1/<br>
│<br>
├── server.py        # Server implementation<br>
├── client.py        # Client implementation<br>
└── README.md<br>


## Required Packages:
```shell
pip install termcolor
pip install pycryptodome
pip install cryptography
```

## Assumption

1) Independent Sum of each client
2) user Input: Opcode
3) Session time: 60 sec
4) when new data come from client then session time again reset to 60 sec
5) exit: for server go offline
6) data user Input: Integer
7) Both keys are Private Keys
8) Diffie hellman parameter(p and q) size is 2048 bytes.
9) if we give opcode 50 as user input then all clients are disconnected but if some clients are in user input mode then you have to enter value to disconnect that clients(it is happening beacause our implementation based on user input).






### Secure Server-Client Communication

Overview

This project demonstrates a secure server-client communication system using cryptographic methods, including Diffie-Hellman Key Exchange, Double DES Encryption, HMAC verification, and session token authentication.

The system includes:

1. Server: Handles client connections, manages encryption, processes data, and ensures secure communication.


2. Client: Connects to the server, exchanges keys, and sends/receives encrypted data.




---

## Features

Diffie-Hellman Key Exchange: Securely generates shared keys between server and client.

Double DES Encryption: Protects sensitive data during transmission.

HMAC Verification: Ensures data integrity and authenticity.

Session Token Authentication: Prevents unauthorized access.

Timeout Handling: Disconnects inactive clients after a set duration.

Multi-threading: Server handles multiple clients simultaneously.



---

## Technologies Used

Python 3.9+

Cryptography Library

PyCrypto (DES Implementation)

Socket Programming

Termcolor for Console Output



---

## Setup and Usage

Prerequisites

1. Python installed on your system.


2. Install the required libraries:
```python
pip install termcolor
pip install pycryptodome
pip install cryptography
```


## Running the Server

1. Open a terminal.


2. Navigate to the directory containing server.py.


3. Run the server:

python server.py

Server Output:
```shell
[SERVER STARTING] indicates the server is starting.

[SERVER LISTENING] shows the server is ready to accept connections.
```



## Running the Client

1. Open another terminal.


2. Navigate to the directory containing client.py.


3. Run the client:
```shell

python client.py

Client Actions:

```
Send data: Enter opcode 30 and a valid integer to send encrypted data to the server.

Disconnect: Enter opcode 50 to terminate the connection.





---

## Workflow

Diffie-Hellman Key Exchange

1. Server generates DH parameters and sends its public key.


2. Client receives the key, generates its private key, and sends its public key.


3. Both compute a shared secret using DH private-public key exchange.



## Session Token

Server generates a random session token and sends it to the client (encrypted with the shared key).

The client includes this token in every message to validate authenticity.


## Secure Communication

1. Double DES Encryption:

Client encrypts messages with two keys (key1 and key2) derived from the shared key.



2. HMAC Verification:

Validates message integrity using HMAC generated with key2.




## Timeout Handling

If no data is received within 60 seconds, the server disconnects the client.


---

## Example Server Output
```shell
[SERVER STARTING] Server is starting...
Enter 'exit' to stop the server: [SERVER LISTENING] Server listening on 127.0.1.1:5566

[NEW CONNECTION] ('127.0.0.1', 50894) connected.
[10] KEY VERIFICATION for client ('127.0.0.1', 50894)
[20] Shared  SESSION KEY to client ('127.0.0.1', 50894)
[TIMER] Client ('127.0.0.1', 50894): 41 seconds remaining
[HMAC VERIFIED SUCCESSFULLY]
[STATUS] Client ('127.0.0.1', 50894): Received 42
[40] Send ENC AGGR RESULT to client ('127.0.0.1', 50894)
[TIMER] Client ('127.0.0.1', 50894): 53 seconds remaining
[HMAC VERIFIED SUCCESSFULLY]
[STATUS] Client ('127.0.0.1', 50894): Received 50
[40] Send ENC AGGR RESULT to client ('127.0.0.1', 50894)
[TIMER] Client ('127.0.0.1', 50894): 0 seconds remaining[TIMEOUT] Client ('127.0.0.1', 50894): Returning  number.
[40] Send ENC AGGR RESULT to client ('127.0.0.1', 50894)
[DISCONNECTED][50] ('127.0.0.1', 50894) connection closed.

exit
[SERVER SHUTTING DOWN] Server is stopping...
[SERVER EXITED][50] Server has shut down.
```
## Example Client Output

```shell
[CONNECTED] Client connected to server at 127.0.1.1:5566
[CLIENT ID] UUID: ca93f22b-43ec-4e62-a4f4-dc26e40e7b45, Integer: 269272234557713870121284243416010357573
[STATUS] Received server's public key.
[STATUS] Loaded server's public key.
[STATUS] Sent client's public key to server.
[STATUS][10] Shared keys derived successfully.
[STATUS][20] Received session token: e3c4f8bfed481813f68ef806f544f8f6

Available Opcodes:
  30 - Send encrypted data
  50 - Disconnect
Enter the opcode (30 to send data, 50 to disconnect): 30
Enter an integer: 42
[STATUS] message number 1 sent.
[SERVER RESULT] Result: 42

Available Opcodes:
  30 - Send encrypted data
  50 - Disconnect
Enter the opcode (30 to send data, 50 to disconnect): 30
Enter an integer: 50
[STATUS] message number 2 sent.
[SERVER RESULT] Result: 92

Available Opcodes:
  30 - Send encrypted data
  50 - Disconnect
Enter the opcode (30 to send data, 50 to disconnect): 50
[STATUS] Disconnection request sent.
[STATUS] Client disconnected.

```
---


---

## Security Features

1. Encrypted Communication:

Prevents interception by encrypting data using Double DES.



2. Integrity Checks:

Uses HMAC to detect tampered data.



3. Session Authentication:

Validates session tokens to prevent replay attacks.





---

## Customization

Timeout Duration: Modify TIMEOUT_DURATION in server.py.

Port and IP: Update PORT and IP variables in both server.py and client.py.

DH Key Size: Change the key_size in generate_dh_parameters.



---

## Troubleshooting

Error: "Failed to connect":

Ensure the server is running and accessible at the specified IP/port.


HMAC Verification Failed:

Ensure the shared keys are correctly derived during key exchange.




---
