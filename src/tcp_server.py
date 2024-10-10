# TCP Server
import socket
import logging
import time

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
# https://hea-www.harvard.edu/~fine/Tech/addrinuse.html
# aceasta linie este pentru un restart rapid
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)
sock.bind(server_address)
logging.info("Serverul a pornit pe %s si portnul portul %d", adresa, port)
sock.listen(5)
try:
    while True:
        logging.info('Asteptam conexiui...')
        conexiune, address = sock.accept()
        logging.info("Handshake cu %s", address)
        try:
            while True:
                data = conexiune.recv(1024)
                logging.info('Content primit: "%s"', data)
                conexiune.send(b"Server a primit mesajul: " + data)
                time.sleep(2)
                data = conexiune.recv(1024)
                logging.info('Content primit: "%s"', data)
                conexiune.send(b"Server a primit mesajul: " + data)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
            break
        finally:
            conexiune.close()
except KeyboardInterrupt:
    logging.info('closing socket')
    sock.close()
    logging.info('KEYBOARD INTERRUPT')