import socket
import traceback
import struct
import time
import random

import matplotlib.pyplot as plt
import os
import requests

from mpl_toolkits.basemap import Basemap
from pip._vendor import requests
from datetime import datetime

#https://medium.com/@MonlesYen/python-for-cybersecurity-29-sniffer-vi-decode-icmp-47a917d6ab42
def decode_icmp_header(data):
    icmp_header_raw = data[20:28]
    # !BBHHH reprezinta formatul in care sunt parsati cei 8 bytes dupa regula din link
    icmp_header = struct.unpack("!BBHHH", icmp_header_raw)

    type = icmp_header[0]
    code = icmp_header[1]

    return {
        "type": type,
        "code": code,
        "checksum": icmp_header[2],
        "packet_id": icmp_header[3],
        "sequence": icmp_header[4]
    }

# https://dev.to/cwprogram/python-networking-ip-header-5fk5
def decode_ip_header(data):
    ip_header = data[:20]  # IP header are primii 20 de btyes
    # formula !BBHHHBBH4s4s reprezinta tipul fiecare elment din headerul de IP pentru a fi parsat din bytes, iar ! este pentru network byte order
    # de exemplu, versiunea + ihl sunt primii 8 biti, 1 byte, si astfel este B, total_length are 16 biti, 2 bytes, si este H, iar 4s reprezinta 32 de biti, 4 bytes
    unpacked_data = struct.unpack("!BBHHHBBH4s4s", ip_header)
    return {
        "version": unpacked_data[0] >> 4,
        "ihl": unpacked_data[0] & 0xF,
        "tos": unpacked_data[1],
        "total_length": unpacked_data[2],
        "identification": unpacked_data[3],
        "flags": unpacked_data[4] >> 13,
        "fragment_offset": unpacked_data[4] & 0x1FFF,
        "ttl": unpacked_data[5],
        "protocol": unpacked_data[6],
        "header_checksum": unpacked_data[7],
        # socket.inet_ntoa va lua forma binara a unei adrese ipv4 din bytes si o va face in format standard cu .
        "source_address": socket.inet_ntoa(unpacked_data[8]),
        "destination_address": socket.inet_ntoa(unpacked_data[9])
    }

# socket de UDP
udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)

# socket RAW de citire a răspunsurilor ICMP
icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
# setam timout in cazul in care socketul ICMP la apelul recvfrom nu primeste nimic in buffer
icmp_recv_socket.settimeout(5)

def traceroute(ip, port):
    # setam TTL in headerul de IP pentru socketul de UDP
    ip_list = []
    TTL = 0
    port = 33433
    while True:
        # if TTL == 30:
        #     return ip_list
        print("")
        TTL = TTL + 1
        port += 1
        if TTL == 64:
            return ip_list
        # print("set ttl")
        udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, TTL)
        print(f"{TTL}\t", end = "")
        # trimite un mesaj UDP catre un tuplu (IP, port)
        udp_send_sock.sendto(b'salut', (ip, port))
        # print("sent")
        # asteapta un mesaj ICMP de tipul ICMP TTL exceeded messages
        # in cazul nostru nu verificăm tipul de mesaj ICMP
        # puteti verifica daca primul byte are valoarea Type == 11
        # https://tools.ietf.org/html/rfc792#page-5
        # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
        addr = 'done!'
        for i in range(4):
            try:
                # print("recvfrom")
                data, addr = icmp_recv_socket.recvfrom(63535)
                # print("recvfrom done")
                # print("IP header")
                # print(decode_ip_header(data))
                # print("ICMP header")
                # print(decode_icmp_header(data))
                # print("IP address")
                # print(addr[0])
                dict_decode = decode_icmp_header(data)
                ip_list.append(addr[0])
                print(addr[0])
                if dict_decode["type"] == 3 and dict_decode["code"] == 3:
                    return ip_list

                break
            except Exception as e:
                # print("Socket timeout ", str(e))
                # print(traceback.format_exc())
                print(" * ", end="")
                if i == 3:
                    # ip_list.append("*")
                    break
            print("")

def rand_ip():
    ipuri = [
    '203.0.113.0', '198.51.100.0', '192.0.2.0', '203.0.113.1', '198.51.100.1',
    '192.0.2.1', '203.0.113.2', '198.51.100.2', '192.0.2.2', '203.0.113.3',
    '198.51.100.3', '192.0.2.3', '203.0.113.4', '198.51.100.4', '192.0.2.4',
    '203.0.113.5', '198.51.100.5', '192.0.2.5', '203.0.113.6', '198.51.100.6',
    '192.0.2.6', '203.0.113.7', '198.51.100.7', '192.0.2.7', '203.0.113.8',
    '198.51.100.8', '192.0.2.8', '203.0.113.9', '198.51.100.9', '192.0.2.9',
    '203.0.113.10', '198.51.100.10', '192.0.2.10', '203.0.113.11', '198.51.100.11',
    '192.0.2.11', '203.0.113.12', '198.51.100.12', '192.0.2.12', '203.0.113.13',
    '198.51.100.13', '192.0.2.13', '203.0.113.14', '198.51.100.14', '192.0.2.14',
    '203.0.113.15', '198.51.100.15', '192.0.2.15', '203.0.113.16', '198.51.100.16',
    '192.0.2.16', '203.0.113.17', '198.51.100.17', '192.0.2.17', '203.0.113.18',
    '198.51.100.18', '192.0.2.18', '203.0.113.19', '198.51.100.19', '192.0.2.19',
    '203.0.113.20', '198.51.100.20', '192.0.2.20', '203.0.113.21', '198.51.100.21']
    return random.choice(ipuri)

def rand_user_agent():
    user_agents = [
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0'
    ]
    return random.choice(user_agents)

def get_locatie_ipapi(ip):
    # exemplu de request la IP info pentru a
    # obtine informatii despre localizarea unui IP
    dict = {}
    raspuns = {}
    for _ in range(5):
        fake_HTTP_header = {
            'referer': 'https://ip-api.com/',
            'user-agent': rand_user_agent(),
            'x-forwarded-for': f'{rand_ip()}, {rand_ip()}, {rand_ip()}'
        }
        # informatiile despre ip-ul 193.226.51.6 pe ipinfo.io
        # https://ipinfo.io/193.226.51.6 e echivalent cu
        raspuns = requests.get(f'http://ip-api.com/json/{ip}', headers=fake_HTTP_header)
        # dict = raspuns.json()
        if raspuns.status_code == 200:
            break
        elif raspuns.status_code == 429:
            print("retry ip query")
            time.sleep(5)
    dict = raspuns.json()
    print(dict)
    rez = {}
    print("-----------------------------------")
    for key, value in dict.items():
        # print(key, value)
        if key == 'city':
            rez[key] = value
        elif key == 'region':
            rez[key] = value
        elif key == 'country':
            rez[key] = value
        elif key == 'lat':
            rez['lat'] = value
        elif key == 'lon':
            rez['lon'] = value
    # rez['city'] = dict['city']
    # rez['region'] = dict['region']
    # rez['country'] = dict['country']
    return rez


def get_locatie_ipinfo(ip):
    # exemplu de request la IP info pentru a
    # obtine informatii despre localizarea unui IP
    dict = {}
    raspuns = {}
    for _ in range(5):
        fake_HTTP_header = {
            'referer': 'https://ipinfo.io/',
            'user-agent': rand_user_agent(),
            'x-forwarded-for': f'{rand_ip()}, {rand_ip()}, {rand_ip()}'
        }
        raspuns = requests.get(f'https://ipinfo.io/widget/{ip}', headers=fake_HTTP_header)
        if raspuns.status_code == 200:
            break
        elif raspuns.status_code == 429:
            print("retry ip query")
            time.sleep(5)
    # informatiile despre ip-ul 193.226.51.6 pe ipinfo.io
    # https://ipinfo.io/193.226.51.6 e echivalent cu
    dict = raspuns.json()
    print(dict)
    rez = {}
    print("-----------------------------------")
    for key, value in dict.items():
        print(key, value)
        if key == 'city':
            rez[key] = value
        elif key == 'region':
            rez[key] = value
        elif key == 'country':
            rez[key] = value
        elif key == 'lat':
            rez['lat'] = value
        elif key == 'lon':
            rez['lon'] = value
        # elif key == ''
    # rez['city'] = dict['city']
    # rez['region'] = dict['region']
    # rez['country'] = dict['country']
    return rez


def get_locatii(ip_list, site = "ip-api"):
    locatii = []
    for ip in ip_list:
        if site == "ip-api":
            act = get_locatie_ipapi(ip)
        elif site == "ipinfo":
            act = get_locatie_ipinfo(ip)
        if act != {}:
            locatii.append((ip, get_locatie_ipapi(ip)))
    return locatii

def draw_map(site, dict_locatii, nume_fisier):
    # facem plotul
    main_map = plt.figure(figsize=(12, 8))
    # facem instanta Bitmap cu proiectia miller cilindrica
    basemap_instance = Basemap(projection='mill',
                llcrnrlat=-60, urcrnrlat=90,
                llcrnrlon=-180, urcrnrlon=180,
                resolution='c')
    # facem malurile si tarile
    basemap_instance.drawcoastlines()
    basemap_instance.drawcountries()
    # basemap_instance.bluemarble()
    act = 1
    # punem un punct pentru fiecare ip gasit
    for ip, loc in dict_locatii:
        lon, lat = loc['lon'], loc['lat']
        to_show = f"{act}. {ip}\n{loc['city']}, {loc['region']}, {loc['country']}"
        act += 1
        x, y = basemap_instance(lon, lat)
        basemap_instance.plot(x, y, 'bo', markersize=5)
        plt.annotate(to_show, xy=(x, y), xytext=(5, 5), textcoords='offset points', fontsize=6, color='red')

    for i in range(len(dict_locatii) - 1):
        lon1, lat1 = dict_locatii[i][1]['lon'], dict_locatii[i][1]['lat']
        lon2, lat2 = dict_locatii[i+1][1]['lon'], dict_locatii[i+1][1]['lat']
        x1, y1 = basemap_instance(lon1, lat1)
        x2, y2 = basemap_instance(lon2, lat2)
        basemap_instance.plot([x1, x2], [y1, y2], 'r-', linewidth=2)
    plt.title(f"Conexiuni pe harta pentru {site}")
    plt.savefig(f"{nume_fisier}.png")
    # plt.show()


def solve(site, nume_tracer, locatie, site_locatie = "ip-api"):
    act_time = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    outfile = open(f"{locatie}-{nume_tracer}-{site_locatie}-{act_time}.txt", "w")
    print("start list")
    lista_rez = traceroute(site, 80)
    print(lista_rez)
    outfile.write(str(lista_rez) + "\n")
    print("end list, start location")
    lista_loc = get_locatii(lista_rez, site_locatie)
    print(lista_loc)
    for el in lista_loc:
        outfile.write(str(el) + "\n")
    print("end location, start map")
    draw_map(site, lista_loc, f"{locatie}-{nume_tracer}-{site_locatie}-{act_time}")
    print("end map")

locatie = input("location: ")
x = int(input("1 - default, 2 - debug\n"))
# varianta = int(input("1 - ip-api, 2 - ipinfo\n"))
# if varianta == 1:
#     site_locatie = "ip-api"
# elif varianta == 2:
#     site_locatie = "ipinfo"
os.chdir("traceroute_files")
if x == 2:
    # print(datetime.now().strftime("%d:%m:%Y:%H:%M:%S"))
    solve("google.com", "google", locatie)
elif x == 1:
    fisier_siteuri = open("siteuri.txt", "r")
    siteuri = fisier_siteuri.readlines()
    fisier_siteuri.close()
    siteuri = [x.strip() for x in siteuri]
    # outfile = open("rezultate.txt", "w")
    # print(siteuri)
    for el in siteuri:
        print(el)
        nume = el.split(".")[1]
        print(nume)
        solve(el, nume, locatie)
        # time.sleep(30)
        # lista_rez = traceroute(el, 80)
        # print(lista_rez)
        # outfile.write(str(lista_rez) + "\n")
        # lista_loc = get_locatii(lista_rez, "ip-api")
        # print("got locatii")
        # for el in lista_loc:
        #     outfile.write(str(el) + "\n")
        # # time.sleep(15)

# lista_rez = traceroute("google.com", 80)
# print(lista_rez)
# lista_loc = get_locatii(lista_rez, "ip-api")
# for el in lista_loc:
#     print(el)






'''
 Exercitiu hackney carriage (optional)!
    e posibil ca ipinfo sa raspunda cu status code 429 Too Many Requests
    cititi despre campul X-Forwarded-For din antetul HTTP
        https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
    si setati-l o valoare in asa fel incat
    sa puteti trece peste sistemul care limiteaza numarul de cereri/zi

    Alternativ, puteti folosi ip-api (documentatie: https://ip-api.com/docs/api:json).
    Acesta permite trimiterea a 45 de query-uri de geolocare pe minut.
'''

# exemplu de request la IP info pentru a
# obtine informatii despre localizarea unui IP
fake_HTTP_header = {
                    'referer': 'https://ipinfo.io/',
                    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36'
                   }
# informatiile despre ip-ul 193.226.51.6 pe ipinfo.io
# https://ipinfo.io/193.226.51.6 e echivalent cu
# raspuns = requests.get('https://ipinfo.io/widget/193.226.51.6', headers=fake_HTTP_header)
# print (raspuns.json())

# print("NEXT")

# pentru un IP rezervat retelei locale da bogon=True
# raspuns = requests.get('https://ipinfo.io/widget/10.0.0.1', headers=fake_HTTP_header)
# print (raspuns.json())

