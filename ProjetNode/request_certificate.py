import socket
import ssl

from OpenSSL import crypto



# Set the file path for the CSR

csr_path = "node.csr"



# Load the private key

with open("private.pem", "rb") as f:

    private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())



# Load the public key

with open("public.pem", "rb") as f:

    public_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())



# Load the CSR

with open(csr_path, "rb") as f:

    csr_pem = f.read()



# Set the server address and port

server_address = "pki.mydomain.local"

server_port = 12345



# Create a TCP socket and connect to the server

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1_2)

sock.connect((server_address, server_port))

print(f"Connected to {server_address}:{server_port}")



# Send the CSR to the server

sock.send(csr_pem)



# Receive the signed certificate from the server

cert_pem = sock.recv(4096).decode("utf-8")

print("Received signed certificate:")

print(cert_pem)



# Save the certificate to a file

with open("node.pem", "w") as f:

    f.write(cert_pem)



# Close the socket

sock.close()