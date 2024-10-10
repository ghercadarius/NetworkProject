# TCP client
import socket
import logging
import time
import sys

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)
import random
import string
logging.info('Handshake cu %s', str(server_address))
sock.connect(server_address)
while True:
    try:
        # generam un mesaj random
        mesaj = ''.join(
          random.choices(string.ascii_uppercase + string.digits, k=10))
        print(mesaj)
        time.sleep(3)
        sock.send(mesaj.encode('utf-8'))
        data = sock.recv(1024)
        logging.info('Content primit: "%s"', data)
    except (RuntimeError, KeyboardInterrupt):
        logging.info('closing socket')
        sock.close()
        logging.info('RUNTIME ERROR or KEYBOARD INTERRUPT')
        break
