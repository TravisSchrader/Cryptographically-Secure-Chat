'''logosnet_server.py
Authors: Travis Schrader, Bo Sullivan
Date: 12/5/21
This program securely implements a client server socket connection using channel
encryption via RSA, and diffie hellman for private messaging.
'''
import socket
import select
import queue
import time
import pickle

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import lnp

MAX_USR = 100
TIMEOUT = 60

def verify_name(pubkey, sig, data):
    '''verify user name with signature'''
    pubkey.verify(
        sig,
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def pack_and_pickle(name, sig):
    '''tuples and serializes the name and sig.'''
    tupple = (name, sig)

    pickled = pickle.dumps(tupple)

    return pickled

def unpack_pickle(pickle_object):
    '''unpacks a serialized pickle tuple'''
    new_pickle = pickle.loads(pickle_object)
    name = new_pickle[0]
    sig = new_pickle[1]
    return name, sig

def get_server_keys():
    '''optional params if you need'''

    with open('server-key-public.pem', 'r') as fil:
        r_pub = RSA.importKey(fil.read())

    with open('server-key-private.pem', 'r') as fil:
        r_priv = RSA.importKey(fil.read())

    return r_pub, r_priv

def is_username(name, usernames):
    '''
    Returns a string code with status of username
    '''
    if (len(name) < 1) or (len(name) > 10) or (' ' in name):
        return "USERNAME-INVALID"

    for value in usernames:
        if name == usernames[value]:
            return "USERNAME-TAKEN"

    return "USERNAME-ACCEPT"



def is_private(msg, usernames):
    '''
    isPrivate returns username of recipient if the msg is private and None otherwise
    '''
    str1 = msg.split(' ')[0]

    if str1[0] == '@':

        user = str1[1:len(str1)]
        for sock in usernames:
            if usernames[sock] == user:
                return user

    return None

def get_sock(user, usernames=None):
    '''Grabs socket for specific user'''
    for sock in usernames:
        if usernames[sock][:-1] == user:
            return sock
    return None

def broadcast_queue(msg, msg_queues, exclude=None):
    '''
    broadcast_queue loads the message into every message queue,
    excluding sockets in the exclude array
    '''
    if exclude is None:
        exclude = []

    if msg and len(msg) <= 1000:
        for sock in msg_queues:
            if sock not in exclude:
                msg_queues[sock].put(msg)


def private_queue(msg, msg_queues, pvt_user, usernames):
    '''
    private_queue loads the message into the queue of the client with the username pvt_user
    '''
    for sock in msg_queues:
        if usernames[sock] == pvt_user:
            msg_queues[sock].put(msg)
            return

def main():
    '''
    Main method. Loops forever until killed
    '''
    args = lnp.get_args(True)
    port = args.port
    the_ip = args.ip

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setblocking(0)
    server.bind((the_ip, port))
    server.listen(5)

    inputs = [server]
    outputs = []
    msg_queues = {}
    n_users = 0
    user_connect_time = {}

    #Dictionaries containing buffered messages and message state variable
    #Key for each is a socket object
    msg_buffers = {}
    recv_len = {}
    msg_len = {}
    usernames = {}
    msg_ids = {}
    symmetric_keys = {}
    msg_id = None

    pub_key, priv_key = get_server_keys()

    ca_pub = None

    #grab the CA's public key
    with open("ca-key-public.pem", 'rb') as fil:
        ca_pub = serialization.load_pem_public_key(
            fil.read(), backend=default_backend()
        )

    decryptor = PKCS1_OAEP.new(priv_key)


    while inputs:

        #if 60 seconds are up no username yet, disconnect the client
        users = list(user_connect_time)
        for sock_fd in users:
            if (time.time() - user_connect_time[sock_fd]) > TIMEOUT:

                lnp.send(sock_fd, '', "EXIT")

                inputs.remove(sock_fd)
                outputs.remove(sock_fd)
                n_users -= 1
                del user_connect_time[sock_fd]


        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for sock_fd in readable:

	    ### Processing server connection requests
            if sock_fd is server:

                connection, client_addr = sock_fd.accept()
                connection.setblocking(0)

                if n_users < MAX_USR:

                    lnp.send(connection, '', "ACCEPT")

                    # NOTE Here we can send the public key
                    #set up connnection variables
                    inputs.append(connection)
                    outputs.append(connection)
                    symmetric_keys[connection] = None
                    n_users += 1
                    user_connect_time[connection] = time.time()

                    if args.debug:
                        print("        SERVER: new connection from " + str(client_addr))

                else: #>100 users
                    lnp.send(connection, '', "FULL")
                    connection.close()

                    if args.debug:
                        print("        SERVER: connection from " +
                              str(client_addr) + " refused, server full")


	 ### Processing client msgs
            else:
                msg_status = lnp.recv(sock_fd, msg_buffers, recv_len, msg_len, msg_ids)


                if msg_id is None:
                    msg_id = msg_status

                # Handling exit correctly, only get in here when msg is complete,
                #  everything needed is in the msg variable
                if msg_status != "LOADING_MSG":
                    msg_id, msg = lnp.get_msg_from_queue(sock_fd, msg_buffers, recv_len, \
                        msg_len, msg_ids, symmetric_keys)

                    if msg_id is not None:
                        msg_status = msg_id

                if msg_status == "MSG_CMPLT":
                    # LEAVE THE LINE BELOW ENABLED FOR TESTING PURPOSES, DO NOT CHANGE IT EITHER
                    # IF YOU ENCRYPT OR DECRYPT msg MAKE SURE THAT WHATEVER IS PRINTED FROM THE
                    # LINE BELOW IS PLAIN TEXT
                    # Note: for the end-to-end encryption clearly you will print whatever
                    #  your receive
                    print("        received " + str(msg) +       " from \
                    " + str(sock_fd.getpeername()))


                    #Username exists for this client, this is a message
                    # NOTE Create an exit() call case to handle exit
                    # NOTE Check cert if the username exsists
                    # NOTE ASK Is S a socket num or a string name???

                    if sock_fd in usernames:
                        # Forward message to person its meant for
                        if msg_id == "DH-HELLO":
                            prv_name, dh_pub = unpack_pickle(msg)
                            send_sock = get_sock(prv_name[1:])

                            lnp.send(sock_fd, msg, "DH-HELLO", symmetric_keys[send_sock])

                        #handle dh-key exchange
                        elif msg_id == "DH-KEY-EXCHANGE":
                            prv_name, dh_pub = unpack_pickle(msg)

                            send_sock = get_sock(prv_name[1:])

                            lnp.send(sock_fd, msg, "DH-KEY-EXCHANGE", symmetric_keys[send_sock])

                        #handle dh-private key name information
                        elif msg_id == "DH_PRIV":
                            prv_name, dh_pub = unpack_pickle(msg)
                            send_sock = get_sock(prv_name[1:])

                            lnp.send(sock_fd, msg, "DH-PRIV", symmetric_keys[send_sock])

                        #dh established, send msg
                        else:
                            pvt_user = is_private(msg, usernames)
                            msg = "> " + usernames[sock_fd] + ": " + msg
                            if pvt_user:
                                private_queue(msg, msg_queues, pvt_user, usernames)
                            else:
                                broadcast_queue(msg, msg_queues, exclude=[sock_fd])

	                #no username yet, this message is a username
                    else:
                        #  continue with username stuff.
                        if msg_id == "SYMKEY":
                            print("Establish channel encryption")

                        # getting username
                        else:
                            username_status = None
                            name_str = None

                            #if connection and sym key establish, handle CA
                            if symmetric_keys[sock_fd] is not None:
                                name2, sig2 = unpack_pickle(msg)
                                name2 = name2.encode()
                                name2 = name2 + b'\n'

                                #verify name and signature
                                try:
                                    verify_name(ca_pub, sig2, name2)
                                    name_str = name2.decode()
                                    username_status = is_username(name_str, usernames)
                                except TypeError:
                                    username_status = "USERNAME-INVALID"


                            lnp.send(sock_fd, '', username_status, symmetric_keys[sock_fd])

                            #CA verified, accept user
                            if username_status == "USERNAME-ACCEPT":
                                usernames[sock_fd] = name_str
                                del user_connect_time[sock_fd]
                                msg_queues[sock_fd] = queue.Queue()
                                msg = "User " + usernames[sock_fd].strip() + " has joined"
                                print("        SERVER: " + msg)
                                broadcast_queue(msg, msg_queues)

                            else: #invalid username
                                user_connect_time[sock_fd] = time.time()
                                msg = None

                # Forward message to person its meant for
                if msg_id == "DH-HELLO" and msg_status != "LOADING_MSG":
                    prv_name, dh_pub = unpack_pickle(msg)

                    # Grab sender username
                    real_sender = '@' + usernames[sock_fd]


                    return_pickle = pack_and_pickle(real_sender, dh_pub)
                    send_sock = get_sock(prv_name[1:], usernames)
                    lnp.send(send_sock, return_pickle, "DH-HELLO", symmetric_keys[send_sock])

                #DH exchange and msg loading done, process message to client
                elif msg_id == "DH-KEY-EXCHANGE" and msg_status != "LOADING_MSG":
                    prv_name, dh_pub = unpack_pickle(msg)
                    # Grab sender username
                    real_sender = '@' + usernames[sock_fd]

                    return_pickle = pack_and_pickle(real_sender, dh_pub)

                    send_sock = get_sock(prv_name[1:].strip(), usernames)

                    lnp.send(send_sock, return_pickle, "DH-KEY-EXCHANGE", symmetric_keys[send_sock])

                #set up for shared secret exchange in DH
                elif msg_id == "DH_PRIV" and msg_status != "LOADING_MSG":
                    prv_name, dh_pub = unpack_pickle(msg)
                    # Grab sender username
                    real_sender = '@' + usernames[sock_fd]

                    return_pickle = pack_and_pickle(real_sender, dh_pub)

                    send_sock = get_sock(prv_name[1:].strip(), usernames)

                    lnp.send(send_sock, return_pickle, "DH_PRIV", symmetric_keys[send_sock])


                # Send the pubkey to the client
                elif msg_id == "AWAIT_PUBKEY" and msg_status != "LOADING_MSG":
                    # send pubkey and message with protocol PUBKEY
                    lnp.send(sock_fd, pub_key.exportKey(), "PUBKEY")

                #handle symkey being establish and starting user as verified
                elif msg_id == "SYMKEY" and msg_status != "LOADING_MSG":
                    plain_text = decryptor.decrypt(msg)
                    symmetric_keys[sock_fd] = plain_text
                    lnp.send(sock_fd, '', "START_USER", symmetric_keys[sock_fd])
                    msg_id = None

	        ### Closing connection with client
                elif msg_id in ("NO_MSG", "EXIT"):
                    if args.debug:
                        print("        SERVER: " + msg_id +
                              ": closing connection with " + str(sock_fd.getpeername()))

                    outputs.remove(sock_fd)
                    inputs.remove(sock_fd)
                    if sock_fd in writable:
                        writable.remove(sock_fd)
                    if sock_fd in msg_queues:
                        del msg_queues[sock_fd]

	                #load disconnect message into msg_queues
                    if sock_fd in usernames:
                        for sock in msg_queues:
                            msg_queues[sock].put("User " + usernames[sock_fd] + " has left")
                        del usernames[sock_fd]

                    if sock_fd in user_connect_time:
                        del user_connect_time[sock_fd]

	         #If user sent disconnect message need to send one back
                    if msg_id == "EXIT":
                        lnp.send(sock_fd, '', "EXIT")

                    n_users -= 1
                    sock_fd.close()


        #Send messages to clients
        for sock_fd in writable:
            if sock_fd in msg_queues:
                try:
                    next_msg = msg_queues[sock_fd].get_nowait()

                except queue.Empty:
                    next_msg = None

                if next_msg:
                    # if args.debug:
                    #     print("        sending " + next_msg + " to " + str(s.getpeername()))
                    # NOTE add encryption?
                    if symmetric_keys[sock_fd] is not None:
                        lnp.send(sock_fd, next_msg, None, symmetric_keys[sock_fd])
                    else:
                        lnp.send(sock_fd, next_msg)


        #Remove exceptional sockets from the server
        for sock_fd in exceptional:

            if args.debug:
                print("        SERVER: handling exceptional condition for \
                    " + str(sock_fd.getpeername()))

            inputs.remove(sock_fd)
	 #if s in outputs:
            outputs.remove(sock_fd)
            del msg_queues[sock_fd]
            del usernames[sock_fd]
            sock_fd.close()


if __name__ == '__main__':
    main()
