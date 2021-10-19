from scapy.all import * # Packet manipulation

pkts = sniff(offline="network_traffic.pcap", count=30) # sniff in a offline way from a pcap file 


print(pkts)

print(pkts[IP])


from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP

print(pkts[IP]) # Stampa tutti gli IP

Dati_TTL = []

#Per ogni pacchetto IP ispezionato ne estrae il contenuto
#pkts[IP].CAMPODESIDERATO
#pkts[IP].payload si accede al pacchetto di strato superiore (Es TCP o UDP)
#pkts[IP].payload.CAMPODESIDERATO
for pacchetti in pkts[IP]:
    print("\n_________________________\n")
    print("Versione IP:  ")
    print(pacchetti.version)
    print("Protocollo:  ")
    print(pacchetti.proto)
    print("TTL :  ")
    print(pacchetti.ttl)
    Dati_TTL.append(pacchetti.ttl)
    print("Destination IP:  ")
    print(pacchetti.dst)
    print("Source IP:  ")
    print(pacchetti.src)
    print("Source Port: ")
    print(pacchetti.payload.sport)
    print("Destination Port: ")
    print(pacchetti.payload.dport)

print("_________________\n")
print("DATI TTL:\n")
print("MAX",max(Dati_TTL))
print("MIN",min(Dati_TTL))
print("AVG",sum(Dati_TTL)/len(Dati_TTL))
print("_________________\n")
