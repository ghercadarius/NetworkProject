import base64
import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSRR
import json

simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind(('165.232.118.13', 53))

def get_config():
    with open('dns_config.json', 'r') as f:
        return json.load(f)


import base64
import os

def fragment_data(data, max_length=100):
    return [data[i:i + max_length] for i in range(0, len(data), max_length)]
def encrypt_file_to_base64(domain_string):
    filename = domain_string.split(".")[0]  # extragem numele fisierului

    for file in os.listdir():
        if file.startswith(filename): # cautam fisierul cu numele respectiv
            filepath = file

            try:
                with open(filepath, "rb") as file_obj:  # deschidem fisierul in mod binar (read binary)
                    file_data = file_obj.read()
                    b64_data = base64.b64encode(file_data)

                    _, extension = os.path.splitext(filepath) # pastram extensia pentru reconstruirea fisierului
                    return f"{b64_data.decode('utf-8')}{extension}"

            except FileNotFoundError:
                return f"File '{filename}' not found"
            except Exception as e:
                return f"Error: {e}"

    return f"No matching file found for '{filename}'"

#domain_string = "Evo.subdomain.abc.xyz"
#result = encrypt_file_to_base64(domain_string)
#fragmented = fragment_data(result)
#print(result)
#print("".join(fragmented))


#Daca nu avem o inregistrare locala, trimitem catre un server public de DNS
def forward(request, forwarder):
    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forward_socket.sendto(request, (forwarder, 53))
    forward_response, _ = forward_socket.recvfrom(512)
    forward_socket.close()
    print("forwarded")
    return forward_response


def is_valid_txt_record(name):
    config = get_config()
    print(config['domains'])
    for domain in config['domains']:
        print(domain)
        if domain in name:
            return True
    return False


# Functia care se ocupa de orice request primit
def handle_dns_request(request):
    packet = DNS(request)
    dns = packet.getlayer(DNS)
    config = get_config()
    if dns and dns.opcode == 0: # dns QUERY
        decoded_name = dns.qd.qname.decode('utf-8').strip('.')
        print ("got: ", decoded_name)
        print (packet.summary())
        if decoded_name in config['domains']:
            print("in local config")
            dns_answer = DNSRR(      # DNS Reply
               rrname=dns.qd.qname, # for question
               ttl=330,             # DNS entry Time to Live
               type="A",
               rclass="IN",
               rdata=config['domains'][decoded_name])
            dns_response = DNS(
                          id = packet[DNS].id, # DNS replies must have the same ID as requests
                          qr = 1,              # 1 for response, 0 for query
                          aa = 0,              # Authoritative Answer
                          rcode = 0,           # 0, nicio eroare http://www.networksorcery.com/enp/protocol/dns.htm#Rcode,%20Return%20code
                          qd = packet.qd,      # request-ul original
                          an = dns_answer)     # obiectul de reply
            return dns_response
        elif is_valid_txt_record(decoded_name):

            print("in base")
            print(decoded_name)
            file_name = base64.b32decode(decoded_name.split(".")[0])
            reconstructed_full_domain_string = file_name.decode('utf-8') + "." + ".".join(decoded_name.split(".")[1:])
            encoded_data = encrypt_file_to_base64(reconstructed_full_domain_string)
            fragments = fragment_data(encoded_data)
            dns_responses = []
            for i, fragment in enumerate(fragments):
                dns_answer = DNSRR(  # DNS Reply
                    rrname=dns.qd.qname,  # for question
                    ttl=330,  # DNS entry Time to Live
                    type="TXT",
                    rclass="IN",
                    rdata=f"{i + 1}/{len(fragments)}:{fragment}")  # include fragment index and total
                dns_response = DNS(
                    id=packet[DNS].id,  # DNS replies must have the same ID as requests
                    qr=1,  # 1 for response, 0 for query
                    aa=0,  # Authoritative Answer
                    rcode=0,  # 0, no error
                    qd=packet.qd,  # original request
                    an=dns_answer)
                dns_responses.append(dns_response)
            return dns_responses
        else:
            return forward(request, config['forwarder'])






while True:
    request, adresa_sursa = simple_udp.recvfrom(65535)
    # converitm payload-ul in pachet scapy
    print(adresa_sursa)
    if (adresa_sursa[1] == 53):
        continue
    responses = handle_dns_request(request)
    print(responses)

    output = ""
    #https://www.isi.edu/nsnam/DIRECTED_RESEARCH/DR_HYUNAH/D-Research/stop-n-wait.html
    if isinstance(responses, list):
        for response in responses:
            print(response.show())
            print(adresa_sursa)
            simple_udp.sendto(bytes(response), adresa_sursa)
            output+=response.an.rdata[0].split(":")[1]
            ack, _ = simple_udp.recvfrom(65535)
            print("FIRST ACK", ack)
            while ack != b'ACK':  # daca nu primesc ACK, trimit din nou acelasi packet
                print("Error: ACK not received")
                simple_udp.sendto(bytes(response), adresa_sursa)
                ack, _ = simple_udp.recvfrom(65535)
                print("CALLED ACK:", ack)

    else:
        simple_udp.sendto(bytes(responses), adresa_sursa)
    print("OUTPUT", output)
simple_udp.close()

