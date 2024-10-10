from scapy.all import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, UDP
import base64


ip = IP(dst='dns.victorcucu.software')
transport = UDP(sport = 52512, dport=53)
dns = DNS(rd=1)
query_str = sys.argv[1]
base32_encoded_domain = base64.b32encode(sys.argv[1].split(".")[0].encode('utf-8'))
query_to_send = base32_encoded_domain.decode('utf-8') + "." + ".".join(query_str.split(".")[1:])
dns_query = DNSQR(qname=query_to_send, qtype=16, qclass=1) # qtype 16 = TXT
dns.qd = dns_query


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
sock.settimeout(10)
sock.bind(('0.0.0.0', 52512))


def collect_fragments():
    fragments = {}
    total_fragments = 0
    received_fragments = 0

    _ = send(ip / transport / dns, verbose=True)
    while received_fragments < total_fragments or total_fragments == 0:
        response, _ = sock.recvfrom(1024)

        print(response)
        received_data = DNS(response)
        received_data = received_data.an.rdata[0].decode('utf-8')
        #print("RECEIVED DNS", received_data[DNS].an.rdata[0].decode('utf-8'))
        #print("AN", response[DNS].an.rdata[0].decode('utf-8'))
        if response and received_data: # and DNS in response and response[DNS].ancount > 0:
                txt_record = received_data

                index, fragment = txt_record.split(":", 1)
                print("INDEX", index)
                print("FRAGMENT", fragment)
                index, total = map(int, index.split("/"))
                fragments[index] = fragment
                print("FRAGMENT", fragment)

                if total_fragments == 0:
                    total_fragments = total

                received_fragments += 1
                # trimite ack pentru fragmentul primit
                ack_pkt = ip / UDP(sport=52152, dport=53) / Raw(load=b'ACK')
                send(ack_pkt, verbose=True)

    return fragments, total_fragments



def reconstruct_message(fragments, total_fragments):
    message = ""

    for fragment in fragments.items():
        print(f"fragment {fragment} out of {total_fragments}")
        message += fragment[1]
    return message


fragments, total_fragments = collect_fragments()
reconstructed_message = reconstruct_message(fragments, total_fragments)
print("RECMESSAGE:", reconstructed_message)

# extragem datele base 64 si extensia fisierului
b64_data, extension = reconstructed_message.split(".", 1)
filename = 'b64.out'
with open(filename, 'wb') as f:
    f.write(bytes(b64_data.encode('utf-8')))
file_data = base64.b64decode(b64_data)

filename = base64.b32decode(base32_encoded_domain).decode('utf-8') + "." + extension
with open(filename, 'wb') as f:
    f.write(file_data)

print(f"Reconstructed file saved as {filename}")