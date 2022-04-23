'''
send and recv functions implementing the chatroom protocol
'''

import struct
import argparse

from Crypto.Cipher import ARC4

import protocol

# ID corresponds to the type of msg being sent, allows us to flow logic
# Key corresponds to the key used for encryption

def send(socket, message='', the_id=None, key=None):
    '''docstrings'''
    utf = message

    if not isinstance(message, (bytes, bytearray)):
        utf = message.encode()

    code = protocol.PACKETS[the_id]

    # Recommended location for symmetric encryption to be implemented as a block cipher
    if key is not None:
        # print("ENCRYPTING")
        # print(utf)
        cipher = ARC4.new(key)
        utf = cipher.encrypt(utf)
        # print(utf)


    payload = struct.pack(
        '>iI{}s'.format(len(utf)),
        code,
        len(utf),
        utf
    )

    socket.send(payload)


def recv(socket, msg_buffers, recv_len, msg_len, msg_ids):
    '''docstrings'''
    if socket not in msg_buffers:
        msg_buffers[socket] = b''
        recv_len[socket] = 0

    try:
        msg = socket.recv(1)
    except socket.ERROR:
        del msg_buffers[socket]
        del recv_len[socket]

        if socket in msg_len:
            del msg_len[socket]

        return 'LOADING_MSG'

    if not msg:
        msg_buffers[socket] = None
        msg_len[socket] = 0

        return 'ERROR'


    msg_buffers[socket] += msg
    recv_len[socket] += 1

    # Check if we have received the first 8 bytes.
    if socket not in msg_len and recv_len[socket] == 8:
        data = struct.unpack('>iI', msg_buffers[socket])

        code = data[0]
        length = data[1]

        msg_buffers[socket] = b''
        msg_len[socket] = length
        msg_ids[socket] = {v: k for k, v in protocol.PACKETS.items()}[code]



    # Check if the message is done buffering.
    if socket in msg_len and len(msg_buffers[socket]) == msg_len[socket]:
        return 'MSG_CMPLT'

    return 'LOADING_MSG'


def get_msg_from_queue(
        socket,
        msg_buffers,
        recv_len,
        msg_len,
        msg_ids,
        symmetric_keys):
    '''docstrings'''
    recv_str = msg_buffers[socket]
    ret_str = ''

    if recv_str is not None:

        # Recommended spot for decryption of symmetric cipher
        if socket in symmetric_keys and symmetric_keys[socket]:
            # print("DECRYPTING")
            cipher = ARC4.new(symmetric_keys[socket])
            recv_str = cipher.decrypt((recv_str))


        try:
            ret_str = recv_str.decode()
        except UnicodeDecodeError:
            ret_str = recv_str

    del msg_buffers[socket]
    del recv_len[socket]
    del msg_len[socket]

    back_id = None

    if socket in msg_ids:
        back_id = msg_ids[socket]
        del msg_ids[socket]

    return back_id, ret_str

def get_args(flag=False):
    '''
    Gets command line argumnets.
    '''

    parser = argparse.ArgumentParser()

    parser.add_argument("--port", metavar='p', dest='port', help="port number", \
        type=int, default=42069)

    parser.add_argument("--ip", metavar='i', dest='ip', help="IP address for client", \
         default='127.0.0.1')

    if flag:
        parser.add_argument("--debug", help="turn on debugging messages", \
            default=True, action="store_false")

    return parser.parse_args()
