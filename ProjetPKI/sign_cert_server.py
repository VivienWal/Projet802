from cryptography import x509

from cryptography.hazmat.primitives import serialization, hashes

from cryptography.hazmat.primitives.asymmetric import rsa, padding

from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from cryptography.hazmat.backends import default_backend

from cryptography.x509.oid import NameOID

from cryptography.x509 import CertificateSigningRequest, Name, SubjectAlternativeName

import datetime

import socket

import crypto

import ssl


# Set the TCP port to listen on

port = 12345



# Create a TCP socket and bind it to the specified port

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

sock.bind(("pki.mydomain.local", port))

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

context.load_cert_chain(certfile="rootCA.pem", keyfile="priv-pki.pem")

sock = context.wrap_socket(sock, server_side=True)


# Listen for incoming connections and handle them one by one

sock.listen()

print(f"Listening on port {port}")

while True:

    conn, addr = sock.accept()

    print(f"Received connection from {addr}")



    # Receive the CSR from the client

    csr_pem = conn.recv(4096).decode("utf-8")

    print("Received CSR:")

    print(csr_pem)

    # Save the certificate to a file

    with open("node.csr", "w") as f:

        f.write(csr_pem)

# Load the root certificate

    with open('rootCA.pem', 'rb') as f:

        root_cert = x509.load_pem_x509_certificate(f.read())



    # Load the root key

    with open('priv-pki.pem', 'rb') as f:

        root_key = serialization.load_pem_private_key(f.read(), password=None)



# Load the CSR

    with open('node.csr', 'rb') as f:

        csr = x509.load_pem_x509_csr(f.read())

#    csr = x509.load_pem_x509_csr(csr_pem)



# Calculate the certificate validity period

    not_valid_before = datetime.datetime.utcnow()

    not_valid_after = not_valid_before + datetime.timedelta(days=365)



# Create the certificate

    builder = x509.CertificateBuilder()

    builder = builder.subject_name(csr.subject)

    builder = builder.issuer_name(root_cert.subject)

    builder = builder.public_key(csr.public_key())

    builder = builder.serial_number(x509.random_serial_number())

    builder = builder.not_valid_before(not_valid_before)

    builder = builder.not_valid_after(not_valid_after)



# Sign the certificate with the root key

    certificate = builder.sign(private_key=root_key, algorithm=hashes.SHA256(), backend=default_backend())



# Write the certificate to disk

    with open('certificate_node_test.pem', 'wb') as f:

        f.write(certificate.public_bytes(Encoding.PEM))



    cert_pem = certificate.public_bytes(Encoding.PEM)



    # Encode the certificate as a PEM-formatted string and send it back to the client

    # Load the certificate into an X509 object

    conn.send(cert_pem)

    print("Sent signed certificate:")

    print()



    # Close the connection

    conn.close()