from OpenSSL import crypto

import os

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import socket

# Set the file paths for the private key and public key

private_key_path = "/home/superv/projet/private.pem"

public_key_path = "/home/superv/projet/public.pem"

csr_path = "/home/superv/projet/node.csr"







# Check if the files already exist

if os.path.exists(private_key_path) and os.path.exists(public_key_path):

    print("Keys already exist")

    # Load the existing keys and use them to generate a CSR, or do other operations as needed

else:

    # Generate a new private key

    key = crypto.PKey()

    key.generate_key(crypto.TYPE_RSA, 4096)



    # Save the private key to a file

    with open(private_key_path, "wb") as f:

        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))



    # Generate a new public key and save it to a file

    public_key = key.to_cryptography_key().public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    with open(public_key_path, "wb") as f:

        f.write(public_key)



    print("New keys generated")



    # Create a new CSR object

    csr = crypto.X509Req()



    # Set the subject of the CSR

    subject = csr.get_subject()

    subject.C = "FR"

    subject.CN = socket.getfqdn()



    csr.set_pubkey(crypto.load_publickey(crypto.FILETYPE_PEM, public_key))

    #csr.set_version(2)

    csr.sign(key, "sha256")

    # Save the CSR to a file

    with open(csr_path, "wb") as f:

        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))



    print("New CSR generated")