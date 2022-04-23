'''logosnet_client.py
Authors: Travis Schrader, Bo Sullivan
Date: 12/5/21
This program securely implements a client server socket connection using channel
encryption via RSA, and diffie hellman for private messaging.
'''
import socket
import select
import queue
import sys
import os
import pickle

# Use serializing to turn the key into bytes
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ARC4
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key

import lnp

# my_file = Path("/path/to/file")
# if my_file.is_file():
#     # file exists

def cert_exists(name: str) -> bool:
    '''see if cert exists in proper dir'''
    #print("In cert check: " + name)
    temp = "/" + name + ".cert"
    dir_path = os.path.dirname(os.path.realpath(__file__))
    test = dir_path + temp
    return os.path.exists(test)

def get_cert_s(name: str):
    '''grabs binary cert string from file'''
    temp = "/" + name + ".cert"
    dir_path = os.path.dirname(os.path.realpath(__file__))
    test = dir_path + temp
    with open(test, 'rb') as fil:
        sig = fil.read()

    return sig

def pack_and_pickle(name, sig):
    '''takes name and sig --> tuple --> pickle'''
    tupple = (name, sig)
    pickle_me = pickle.dumps(tupple)

    return pickle_me

def unpack_pickle(pickle_object):
    '''takes a pickle and unpacks it'''
    new_pickle = pickle.loads(pickle_object)
    name = new_pickle[0]
    sig = new_pickle[1]

    return name, sig

#Main method
def main():
    '''
    uses a select loop to process user and server messages. Forwards user input to the server.
    '''

    args = lnp.get_args()
    server_addr = args.ip
    port = args.port

    server = socket.socket()
    server.connect((server_addr, port))

    msg_buffer = {}
    recv_len = {}
    msg_len = {}
    msg_ids = {}
    symmetric_keys = {}

    initial_dh_msg = None

    intended_user = ""
    username_temp = None

    prv_users = {}

    curr_dh_hello = None

    #prime to use for diffie-hellman
    str_prime = "0x1C5C72CCE8732C04D77922B5436853864BBE1F \
    918B0104EC5A31C66BC9E1750DFAAEAF4A78D0BA7CD16101E6C4E \
    09609B7CAB8001E93F5EBEFD3C244D32670948BFBC83E9373EEA9 \
    9763032364D426769794050B8B8FFBB38C5B97847161D45730E24 \
    BFB817BA285EDFD"

    #change prime to please pylint
    str_prime = str_prime.replace(" ", "")
    prime = str_prime.strip(" ").encode().decode('ascii')
    prime = int(prime, 16)

    g_prime = 2

    #dh shared params
    params_numbers = dh.DHParameterNumbers(prime, g_prime)
    parameters = params_numbers.parameters(default_backend())

    #load client keys
    client_private_key = parameters.generate_private_key()

    client_public_key = client_private_key.public_key().  \
    public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    # NOTE Use this to hold the sym key used with the server
    my_sym_key = get_random_bytes(16)
    sym_key_sent = False

    pub_key = None

    cert_verified = False

    inputs = [server, sys.stdin]
    outputs = [server]
    message_queue = queue.Queue()

    waiting_accept = True
    username = ''
    username_next = False

    while server in inputs:

        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for sock_fd in readable:

            ### Process server messages
            if sock_fd == server:
                # This point may iterate multiple times until the message is completely
                #  read since lnp.recv, receives a few bytes at a time.
                code = lnp.recv(sock_fd, msg_buffer, recv_len, msg_len, msg_ids)

                # This will not happen until the message is switched to MSG_COMPLETE when then
                # it is read from the buffer.
                if code != "LOADING_MSG":
                    code_id, msg = lnp.get_msg_from_queue(sock_fd, msg_buffer, recv_len, \
                        msg_len, msg_ids, symmetric_keys)

                    if code_id is not None:
                        code = code_id

                if code == "MSG_CMPLT":

                    if username_next:
                        #print user info to terminal
                        username = username_temp
                        username_msg = msg
                        sys.stdout.write(username_msg + '\n')
                        sys.stdout.write("> " + username + ": ")
                        sys.stdout.flush()
                        username_next = False

                    elif msg:
		                #If username exists, add message prompt to end of message
                        if username != '':
                            sys.stdout.write('\r' + msg + '\n')
                            sys.stdout.write("> " + username + ": ")

                        #If username doesnt exist, just write message
                        else:
                            sys.stdout.write(msg)

                        sys.stdout.flush()

                # This and any other codes can be edited in protocol.py, this way
                # you can add new codes for new states, e.g., is this a public key,
                #  CODE is PUBKEY and msg contains the key.
                elif code == "ACCEPT":
                    message_queue.put("AWAIT_PUBKEY")
                    waiting_accept = False
                    sys.stdout.write(msg)
                    sys.stdout.flush()

                # Accept pubkey and create symmetric key.
                # NOTE
                elif code == "PUBKEY":
                    # got the pubkey now initialize it as a RSA key
                    pub_key = RSA.importKey(msg)

                    message_queue.put("PUBKEY")
                    # use pubkey to encrypt our key, this is now the symmetric key.


                # Prompt username input
                elif code == "START_USER":
                    code = "START_USER"

                #handle invalid names, taken names
                elif code in ("USERNAME-INVALID", "USERNAME-TAKEN"):
                    sys.stdout.write(msg)
                    sys.stdout.flush()

                #accept name
                elif code == "USERNAME-ACCEPT":
                    cert_verified = True
                    username_next = True

                #exit message
                elif code in ("NO_MSG", "EXIT"):
                    sys.stdout.write(msg + '\n')
                    sys.stdout.flush()
                    inputs.remove(sock_fd)
                    if sock_fd in writable:
                        writable.remove(sock_fd)

                # Recieved key first case for DH
                elif code == "DH-HELLO":

                    prv_name, dh_pub = unpack_pickle(msg)
                    curr_dh_hello = prv_name
                    temp_key = load_der_public_key(dh_pub, default_backend())
                    prv_users[prv_name.strip()] = client_private_key.exchange(temp_key)

                    message_queue.put("DH-HELLO")

                # Sent key first case for DH
                elif code == "DH-KEY-EXCHANGE":
                    prv_name, dh_pub = unpack_pickle(msg)
                    temp_key = load_der_public_key(dh_pub, default_backend())
                    prv_users[prv_name.strip()] = client_private_key.exchange(temp_key)

                    # Sending stored dh message from dh initialization
                    cipher = ARC4.new(prv_users[prv_name.strip()])

                    msg_encrypt_dh = cipher.encrypt(initial_dh_msg.encode())
                    package = pack_and_pickle(intended_user, msg_encrypt_dh)
                    lnp.send(sock_fd, package, "DH_PRIV", my_sym_key)

                #handle dh_priv key and process message
                elif code == "DH_PRIV":

                    prv_name, msg_rcv = unpack_pickle(msg)

                    cipher = ARC4.new(prv_users[prv_name.strip()])
                    recv_str_dh = cipher.decrypt((msg_rcv))

                    sys.stdout.write("\n" + prv_name.strip() + ": " + recv_str_dh.decode() + "\n")
                    sys.stdout.flush()

            ### Process user input
            else:

                msg = sys.stdin.readline()

                if not waiting_accept:
                    msg = msg.rstrip()

                    # this checks if sym key has been set up yet if not we still need it,
                    # once sym key is set up we can send a username
                    if msg and sym_key_sent:
                        message_queue.put(msg)
                    if not ((username == '') or (msg == "exit()")):
                        sys.stdout.write("> " + username + ": ")
                        sys.stdout.flush()

        ###
        ### Send messages to server
        ###
        for sock_fd in writable:

            try:
                msg = message_queue.get_nowait()
            except queue.Empty:
                msg = None

	 #if there is a message to send
            if msg:

	     #if exit message, send the exit code
                if msg == "exit()":
                    outputs.remove(sock_fd)
                    lnp.send(sock_fd, '', "EXIT")

                elif msg == "AWAIT_PUBKEY":
                    lnp.send(sock_fd, '', "AWAIT_PUBKEY")

                # need to encrypt sym key.
                elif msg == "PUBKEY":
                    encryptor = PKCS1_OAEP.new(pub_key)
                    cipher_text = encryptor.encrypt(my_sym_key)

                    lnp.send(sock_fd, cipher_text, "SYMKEY")
                    sym_key_sent = True
                    symmetric_keys[sock_fd] = my_sym_key


                # Username negotiation
                elif sym_key_sent and not cert_verified:
                    if cert_exists(msg):
                        username_temp = msg.strip()
                        sig = get_cert_s(msg)

                        #pack SIG and NAME in tuple
                        package = pack_and_pickle(msg, sig)

                        #send away
                        lnp.send(sock_fd, package, None, my_sym_key)

                elif msg == "DH-HELLO":
                    package = pack_and_pickle(curr_dh_hello, client_public_key)
                    lnp.send(server, package, "DH-KEY-EXCHANGE", my_sym_key)

	            #otherwise just send the messsage
                else:

                    # check private msg
                    if msg[0] == '@':

                        intended_user = msg.split(' ')[0]
                        if intended_user not in prv_users:
                            initial_dh_msg = ' '.join(msg.split()[1:])
                            package = pack_and_pickle(intended_user, client_public_key)
                            lnp.send(sock_fd, package, "DH-HELLO", my_sym_key)

                        else:
                            #NOTE Need to encrypt msg using shared key before packing and sending
                            cipher = ARC4.new(prv_users[intended_user.strip()])
                            msg_encrypt_dh = cipher.encrypt(msg.split(' ', 1)[1].strip())
                            package = pack_and_pickle(intended_user, msg_encrypt_dh)
                            lnp.send(sock_fd, package, "DH_PRIV", my_sym_key)

                    # normal msg
                    else:
                        lnp.send(server, msg, None, my_sym_key)

        for sock_fd in exceptional:
            print("Disconnected: Server exception")
            inputs.remove(sock_fd)

    server.close()

if __name__ == '__main__':
    main()
