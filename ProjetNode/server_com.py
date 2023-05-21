import socket
import ssl
import socket
from Crypto.Cipher import AES
from time import sleep
from Crypto.Util import Padding
import os
import threading
import select

HOST = socket.getfqdn()
PORT_KEY = 60000
PORT_MSG = 50000

# set up TLS context
#context = ssl.create_default_context()
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
#context.set_ciphers('ECDHE-RSA-AES128-SHA256')
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations('/home/superv/projet/rootCA.pem')
context.load_cert_chain(keyfile="private.pem", certfile="node.pem")


if __name__ == "__main__":
    iv = b'1234567890123456'
    global sym_key
    sym_key = {}
    # Définition d'un verrou
    verrou = threading.Lock()

    def encrypt(message,key):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = Padding.pad(message, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        return ciphertext

    def decrypt(ciphertext,key):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = cipher.decrypt(ciphertext)
        message = Padding.unpad(padded_message, AES.block_size)
        return message.rstrip(b"\0")

    
    def handle_client_key(conn,addr):
        global sym_key, verrou
        try:
            with conn:
                data = conn.recv(1024)
                key = data
                print('Echange clé symetrique', key.decode('utf-8'))
                #print(type(key))
                # Ouvrir un fichier en mode écriture
                with verrou:
                    sym_key = key
        except Exception as e:
            print(e)
        finally:
            conn.close()


    def handle_client_msg(conn,addr):
        global sym_key, verrou
        with conn:
            key = sym_key
            #print('Connected by', addr[0])
            #print('Echange message avec', socket.gethostbyaddr(addr[0])[0].split('.')[0])
            #print('key ', key)
            while True:
                try:
                    
                # Receive encrypted message from client
                    data = conn.recv(1024)
                    if not data:
                        break
                    #print(data)
                    #print(addr[0])
                    #print(key)

                # Decrypt the message
                    plaintext = decrypt(data,key)

                # Print the decrypted message
                    print('Message reçu :', plaintext.decode('utf-8'))

                # Echo the message back to the client (encrypted)
                    ciphertext = encrypt(plaintext,key)
                    conn.sendall(ciphertext)
                except ConnectionResetError:
                    print("Client closed the connection")
                    break


    def listen_key():
        global sym_key, verrou

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
            c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            c.bind((HOST, PORT_KEY))
            c.listen(5)
            with context.wrap_socket(c, server_side=True) as ssl_socket:
                while True:
                    conn, addr = ssl_socket.accept()
                    #print(conn)
                    threading.Thread(target=handle_client_key, args=(conn, addr,)).start()
                     #c.close()
                sleep(1)
                    #ssl_socket.close()
                #c.close()

    def listen_msg():
        global sym_key, verrou

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT_MSG))
            s.listen(5)
            while True:
                conn, addr = s.accept()
                #print(conn)
                threading.Thread(target=handle_client_msg, args=(conn, addr,)).start()
            s.close()

    # Création des threads pour exécuter les deux fonctions en parallèle
    thread_1 = threading.Thread(target=listen_key)
    thread_2 = threading.Thread(target=listen_msg)

    # Démarrage des threads
    thread_1.start()
    thread_2.start()

    # Attente de la fin des threads
    thread_1.join()
    thread_2.join()