import pandas as pd

from scapy .all import * # importing scapy library

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP

import matplotlib.pyplot  as plt
CaptureFileName = "network_traffic.pcap" 

TableColumnsName = ['IP'] + ['SourcePort'] + ['DestinationPort'] + ['HigherLevelProtocol'] + ['TTL'] + ['Length']
Table = pd.DataFrame(columns=TableColumnsName)

i=0
TTL =[]
def AnalyzePacket(packet):
    global i
    DataTable = []
    global Table
    for pacchetti in packet[IP]:
        #IP_Counter[pacchetti.src] = IP_Counter.get(pacchetti.src,0) + 1
        try:
            #Creo una lista con i dati della mi ariga
            DataTable.append(pacchetti.src)
            DataTable.append(pacchetti.payload.sport)
            DataTable.append(pacchetti.payload.dport)
            DataTable.append(pacchetti.proto)
            DataTable.append(pacchetti.ttl)
            DataTable.append(pacchetti.len)

            TTL.append(pacchetti.ttl)

            #Creo una tabella con una sola riga
            new_row = pd.DataFrame([DataTable], columns=TableColumnsName)
            #Concateno la nuova riga la vacchia tabella
            Table = pd.concat([Table, new_row], axis=0)
            pass
        except:
            pass
        

  
    
    if i%20 == 0:
         os.system('cls' if os.name == 'nt' else 'clear')
    if i%10 == 0:
        '''IpTrafficPlot = Table['.groupby("IP")['Length'].sum()']
        IpTrafficPlot = IpTrafficPlot.sort_values(ascending=False)
        IpTrafficPlot = IpTrafficPlot.iloc[0:10]
        IpTrafficPlot.plot(kind='barh', figsize=(8,2))'''

        
        plt.scatter(i, pacchetti.ttl)
        plt.pause(0.05)
    i = i+1
    return '....'#f"{packet[0][1].src} ==> {packet[0][1].dst}"

pkts = sniff(offline=CaptureFileName ,prn=AnalyzePacket,count=1000)

Table = Table.reset_index()
Table = Table.drop(columns="index")


#Table=Table.sort_values('Length')

#print(Table[TableColumnsName])
PortTraffic = Table.groupby("SourcePort")['Length'].sum()

PortTraffic = PortTraffic.sort_values(ascending=False)
#print(PortTraffic)

IpTraffic = Table.groupby("IP")['Length'].sum()

IpTraffic = IpTraffic.sort_values(ascending=False)
#print(IpTraffic)

#Creo una tabella che raggrupa i dati per IP e SourcePort/DestinationPort/Protocol
#Successivamente per ogni coppia calcola la dimensione totale del traffico generato
IpTraffic = IpTraffic.iloc[0:10]
SourcePortion       = Table.groupby(["IP","SourcePort"])['Length'].sum()
DestinationPortion  = Table.groupby(["IP","DestinationPort"])['Length'].sum()
BestProtocolPortion = Table.groupby(["IP","HigherLevelProtocol"])['HigherLevelProtocol'].count() #Conta quante volte appare quel protocollo


print(SourcePortion)
print(DestinationPortion)
print(BestProtocolPortion)

print("BEST IP\n")

BestIpTableName = ['ip_addr'] + ['amount_of_total_traffic'] + ['protocol'] + ['amount_of_traffic_for_specific_protocol'] + ['source_port']+['amount_for_spec_source_port']+['destination_port']+['amount_for_spec_destination_port']
BestIpTable = pd.DataFrame(columns=BestIpTableName)
DataTable = []
#Per ognuno degli ip più usati estrae dalle tabelle precedenti le corrispettive porte dst/src e il protocollo più usato
for BestIp in IpTraffic.keys():
    print(BestIp," -> ", IpTraffic[BestIp])
    
    BestSourcePortTrafficPortion = SourcePortion.loc[BestIp]
    #BestSourcePortTrafficPortion.sort_values()

    #BestSourcePortTrafficPortion = BestSourcePortTrafficPortion.idxmax()

    BestDestinationPortTrafficPortion = DestinationPortion.loc[BestIp]
    #BestDestinationPortTrafficPortion.sort_values()

    #BestDestinationPortTrafficPortion = BestDestinationPortTrafficPortion.idxmax()

    BestprotocolTrafficPortion = BestProtocolPortion.loc[BestIp]
    #BestprotocolTrafficPortion.sort_values()

    #BestprotocolTrafficPortion = BestprotocolTrafficPortion.idxmax()

    #TableCreation:
    '''DataTable.append(BestIp)
    DataTable.append(IpTraffic[BestIp])
    DataTable.append(BestprotocolTrafficPortion.idxmax())
    DataTable.append(BestprotocolTrafficPortion[BestprotocolTrafficPortion.idxmax()])
    DataTable.append(BestSourcePortTrafficPortion.idxmax())
    DataTable.append(BestSourcePortTrafficPortion[BestSourcePortTrafficPortion.idxmax()])
    DataTable.append(BestDestinationPortTrafficPortion.idxmax())
    DataTable.append(BestDestinationPortTrafficPortion[BestDestinationPortTrafficPortion.idxmax()])

    new_row = pd.DataFrame([DataTable], columns=BestIpTableName)
    BestIpTable = pd.concat([BestIpTable, new_row], axis=0)'''
    #print("\nSrc Port: ",BestSourcePortTrafficPortion,"\nDst Port: ",BestDestinationPortTrafficPortion,"\nProto: ",BestprotocolTrafficPortion)

print(BestIpTable)


#PortTraffic.to_csv("task1.csv")
#PortTraffic.to_csv("task4.csv")



IpTraffic.plot(kind='barh', figsize=(8,2))
plt.show()
print(IpTraffic)


'''for count in range(0,10):
    print(IpTraffic.iloc[count])'''
'''
plt.show()

MostFrequentIP = []
#Seleziona le specifiche rige in base al valore di una colonna
for SelectedIP in MostFrequentIP:
    SpecificIpTable = Table.loc[df['IP'] == SelectedIP]

    Protocols      = SpecificIpTable.groupby("HigherLevelProtocol")['Length'].sum() #MostFrequentProtocol traffic
    print(Protocols)
    #MostFrequentProtocols = Protocol.
    SourceProtocols=  SpecificIpTable.groupby("SourcePort")['Length'].sum() #SourcePortMostFrequentPort traffic
    print(SourceProtocols)
    # SourcePortMostFrequentPorts
    DestinationProtocols = SpecificIpTable.groupby("DestinationPort")['Length'].sum() #DestinationPortMostFrequentPort traffic
    print(DestinationProtocols)
    # SourcePortMostFrequentPortss
'''

