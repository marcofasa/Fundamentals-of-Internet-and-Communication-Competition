import pandas as pd

from scapy .all import * # importing scapy library

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP

import matplotlib.pyplot  as plt
CaptureFileName = "network_traffic.pcap"                                        #.pcap File name
                                                                                #Create a list that contain coulomns names
TableColumnsName = ['IP'] + ['SourcePort'] + ['DestinationPort'] + ['HigherLevelProtocol'] + ['TTL'] + ['Length']                                             

i=0                                                                             #Flag counter (used in analyzePacketFunction)
TableData = []

def AnalyzePacket(packet):
    global i                                                                    #
    DataRow = []                                                              #Create an empty line                                                            #Access my global table variable(panda dataframe)
    global TableData                                                               #Access my global table variable(panda dataframe)
    for pacchetti in packet[IP]:                                                #For each packet it will extract task 1 information
        try:
            DataRow.append(pacchetti.src)
            DataRow.append(pacchetti.payload.sport)
            DataRow.append(pacchetti.payload.dport)
            DataRow.append(pacchetti.proto)
            DataRow.append(pacchetti.ttl)
            DataRow.append(pacchetti.len)
           
            TableData.append(DataRow)
            pass
        except:
            pass
    
        if i%1000 == 0:
            os.system('cls' if os.name == 'nt' else 'clear')                       #Nice loading bar
            print("---",i,"---")

    i = i+1
    return


####################################################################################
#Start Program
####################################################################################


pkts = sniff(offline=CaptureFileName ,prn=AnalyzePacket,store=0)             #Sniff packet one by one
                                                                                #pnr function is called for each packet
Table = pd.DataFrame.from_records( TableData, columns=TableColumnsName) 

Table = Table.reset_index()                                                     #Panda dataframe index reset
Table = Table.drop(columns="index")

IpTraffic = Table.groupby("IP")['Length'].sum()                                 #Group together rows with same ip and sum their portion of traffic
IpTraffic = IpTraffic.sort_values(ascending=False)                              #Sort the Ip by traffic

TopIP = IpTraffic.iloc[0:10]                                                    #Keep only the best 10 ip
print(TopIP)
SourcePortion       = Table.groupby(["IP","SourcePort"])['Length'].sum()
DestinationPortion  = Table.groupby(["IP","DestinationPort"])['Length'].sum()
BestProtocolPortion = Table.groupby(["IP","HigherLevelProtocol"])['Length'].sum() #Conta quante volte appare quel protocollo

BestIpTableName = ['ip_addr'] + ['amount_of_total_traffic'] + ['protocol'] + ['amount_of_traffic_for_specific_protocol'] + ['source_port']+['amount_for_spec_source_port']+['destination_port']+['amount_for_spec_destination_port']
BestIpTable = pd.DataFrame(columns=BestIpTableName)



#Per ognuno degli ip più usati estrae dalle tabelle precedenti le corrispettive porte dst/src e il protocollo più usato
for TopIp in TopIP.keys():
    #print(TopIp," -> ", IpTraffic[TopIp])
    
    DataTable = []
    BestSourcePortTrafficPortion = SourcePortion.loc[TopIp]                                        #Extract from the Ip-Port pair only the pair which contain one of the TOPIP
    BestDestinationPortTrafficPortion = DestinationPortion.loc[TopIp]                              #Same but with dest port
    BestprotocolTrafficPortion = BestProtocolPortion.loc[TopIp]                                    #Same but with Protocol

                                                                                                   #Save Data to insert in table
    DataTable.append(TopIp)
    DataTable.append(IpTraffic[TopIp])
    DataTable.append(BestprotocolTrafficPortion.idxmax())
    DataTable.append(BestprotocolTrafficPortion[BestprotocolTrafficPortion.idxmax()])              #the ammount of traffic of the most used src port
    DataTable.append(BestSourcePortTrafficPortion.idxmax())
    DataTable.append(BestSourcePortTrafficPortion[BestSourcePortTrafficPortion.idxmax()])          #the ammount of traffic of the most used dst port
    DataTable.append(BestDestinationPortTrafficPortion.idxmax())
    DataTable.append(BestDestinationPortTrafficPortion[BestDestinationPortTrafficPortion.idxmax()])#the ammount of traffic of the most used protocol

    new_row = pd.DataFrame([DataTable], columns=BestIpTableName)                                    #create new row
    BestIpTable = pd.concat([BestIpTable, new_row], axis=0)


BestIpTable.to_csv("task3.csv",index=False)                                           #Save Result on a csv file