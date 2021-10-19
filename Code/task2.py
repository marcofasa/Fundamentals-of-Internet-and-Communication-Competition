import pandas as pd

from scapy .all import * # importing scapy library

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP

import matplotlib.pyplot  as plt
CaptureFileName = "network_traffic.pcap"                                        #.pcap File name

TableColumnsName =['ip_addr'] + ['amount_of_traffic']                           #Create a list that contain coulomns names

i=0                                                                             #Flag counter (used in analyzePacketFunction)

TableData = []
def AnalyzePacket(packet):
    global i                                                                    #
    DataRow = []                                                                #Create an empty line                                                            #Access my global table variable(panda dataframe)
    global TableData                                                            #Access my global table variable(panda dataframe)
    for pacchetti in packet[IP]:                                                #For each packet it will extract task 1 information
        try:
            DataRow.append(pacchetti.src)                                       #IP         column
            DataRow.append(pacchetti.len)                                       #Length      column
           
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


pkts = sniff(offline=CaptureFileName ,prn=AnalyzePacket,store=0)                #Sniff packet one by one

Table = pd.DataFrame.from_records( TableData, columns=TableColumnsName)         #pnr function is called for each packet

Table = Table.reset_index()                                                     #Panda dataframe index reset
Table = Table.drop(columns="index")

IpTraffic = Table.groupby("ip_addr")['amount_of_traffic'].sum()                 #Group together rows with same ip and sum their portion of traffic
IpTraffic = IpTraffic.sort_values(ascending=False)                              #Sort the Ip by traffic

TopIP = IpTraffic.iloc[0:10]                                                    #Keep only the best 10 ip

plt.title("Top 10 IP")
plt.xlabel("Ammount of traffic [Byte]")
plt.ylabel("IP")

TopIP.plot(kind='barh', figsize=(8,2))
plt.savefig('task2.png')
plt.show()

TopIP = pd.DataFrame({'ip_addr':TopIP.index, 'amount_of_traffic':TopIP.values})
TopIP.to_csv("task2.csv",index=False)                                           #Save Result on a csv file