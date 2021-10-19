import pandas as pd

from scapy .all import * # importing scapy library

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP

import matplotlib.pyplot  as plt
CaptureFileName = "network_traffic.pcap"                                        #.pcap File name

TableColumnsName =['port_number'] + ['amount_of_traffic']                       #Create a list that contain coulomns names
Table = pd.DataFrame(columns=TableColumnsName)                                  #Create an empty dataframe with The predeclared coulomns names

i=0                                                                             #Flag counter (used in analyzePacketFunction)

TableData = []

def AnalyzePacket(packet):
    global i                                                                    
    DataRow = []                                                              #Create an empty line                                                            #Access my global table variable(panda dataframe)
    global TableData
    #global Table
    for pacchetti in packet[IP]:                                              #For each packet it will extract task 1 information
        try:

            DataRow.append(pacchetti.payload.sport)                           #Source Port Coulomn
            DataRow.append(pacchetti.len)                                     #Length      Coulomn
            
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
                                                                                #pnr function is called for each packet
Table = pd.DataFrame.from_records( TableData, columns=TableColumnsName)
print(Table)
Table = Table.reset_index()                                                     #Panda dataframe index reset
Table = Table.drop(columns="index")

PortTraffic = Table.groupby("port_number")['amount_of_traffic'].sum()           #Group together row with same source port

PortTraffic = PortTraffic.sort_values(ascending=False)                          #Sort row by bigger traffic ammount

PortTraffic = pd.DataFrame({'port_number':PortTraffic.index, 'amount_of_traffic':PortTraffic.values})

PortTraffic.to_csv("task1.csv",index=False)                    #Save Result on a csv file