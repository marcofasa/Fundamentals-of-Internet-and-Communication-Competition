import pandas as pd

from scapy .all import * # importing scapy library

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP

import matplotlib.pyplot  as plt
import numpy as np

CaptureFileName = "network_traffic.pcap"                                        #.pcap File name

TableColumnsName = ['ttl']                                                      #Create a list that contain coulomns names

i=0                                                                             #Flag counter (used in analyzePacketFunction)

TableData = []
def AnalyzePacket(packet):
    global i                                                                    #
    DataRow = []                                                                #Create an empty line
    global Table                                                                #Access my global table variable(panda dataframe)
    for pacchetti in packet[IP]:                                                #For each packet it will extract task 1 information
        try:
            DataRow.append(pacchetti.ttl)                                        #ttl         Culomn
           
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

Table = Table.reset_index()                                                     #Panda dataframe index reset
Table = Table.drop(columns="index")

DataTable = []

Min = Table['ttl'].min()
Max = Table['ttl'].max()
Avg = Table.mean()['ttl']
Var = Table.var()['ttl']

DataTable.append(Min)
DataTable.append(Max)
DataTable.append(round(Avg,2))
DataTable.append(round(Var,2))

TableColumnsName = ['min']+['max']+['average']+['variance']
Table = pd.DataFrame([DataTable], columns=TableColumnsName)

Table.to_csv("task4.csv",index=False)                                           #Save Result on a csv file

#column