import socket
import ssl
import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from time import sleep
from Crypto.Util import Padding

#HOST = "node2.mydomain.local"
HOST = "pki.mydomain.local"
PORT_KEY = 60000
PORT_MSG = 50000

# set up TLS context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
#context.set_ciphers('ECDHE-RSA-AES128-SHA256')
context.load_verify_locations('/home/superv/projet/rootCA.pem')
context.load_cert_chain(keyfile="private.pem", certfile="node.pem")


if __name__ == "__main__":
    iv = b'1234567890123456'

    def encrypt(message):
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        padded_message = Padding.pad(message, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        return ciphertext

    def decrypt(ciphertext):
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        padded_message = cipher.decrypt(ciphertext)
        message = Padding.unpad(padded_message, AES.block_size)
        return message.rstrip(b"\0")


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
        c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        node_dst = input('Renseigner le numéro du noeud de destination : ')
        c.connect((HOST, PORT_KEY + int(node_dst)))
        #c.connect((HOST, PORT_KEY))
        random_bytes = os.urandom(32)
        key = base64.b64encode(random_bytes).decode('utf-8')[0:16]
        #print(key)
        #print(key.encode('utf-8'))
        with context.wrap_socket(c) as ssl_socket:
            ssl_socket.sendall(key.encode("utf-8"))
            #c.close()
            sleep(3)
            ssl_socket.close()
        #c.close()


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((HOST, PORT_MSG + int(node_dst)))
        #s.connect((HOST, PORT_MSG))
        while True:
            # Prompt the user for a message to send
            message = input('Enter message to send: ')


            # Send the encrypted message and IV to the server
            ciphertext = encrypt(message.encode('utf-8'))
            s.sendall(ciphertext)

            # Receive and decrypt the server's response
            data = s.recv(1024)
            plaintext = decrypt(data)

            # Print the decrypted message
            print('Received:', plaintext.decode('utf-8').rstrip('\0'))
        s.close()