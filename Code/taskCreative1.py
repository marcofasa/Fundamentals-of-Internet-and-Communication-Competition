import pandas as pd

from scapy .all import * # importing scapy library

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP

import matplotlib.pyplot  as plt
import random 

plt.xlabel('N ° Packet')
plt.title('ConnectionsHistory')

#The idea is to print a real time graph that show whenever a new connection is opened or closed


CaptureFileName = "network_traffic.pcap"                                        #.pcap File name
                                                                                #Create a list that contain coulomns names
TableColumnsName = ['IP'] + ['SourcePort'] + ['DestinationPort'] + ['HigherLevelProtocol'] + ['TTL'] + ['Length'] + ['Syn']+['Fin']                                            
Table = pd.DataFrame(columns=TableColumnsName)                                  #Create an empty dataframe with The predeclared coulomns names

i=0                                                                             #Flag counter (used in analyzePacketFunction)

GraficcoFlag = []
plt.scatter(0, 8)
def AnalyzePacket(packet):
    global i                                                                    #
    DataTable = []                                                              #Create an empty line
    global Table                                                                #Access my global table variable(panda dataframe)
    for pacchetti in packet[IP]:                                                #For each packet it will extract task 1 information
        try:
            FIN = 0x01
            SYN = 0x02

            Flag = pacchetti.payload.flags                                      #Extract the flag field of tcp packet
            Str = ""
            rnd =random.randint(0,20) * 0.20                                    #Random number for avoid overlap on graph annotation
            if i%2:                                                             #Other strategy to avoid overlap of annotation
                rnd = rnd *-1
                                                                                #Generate the annotation that will be printed on the graph
            Str = Str + "IP: "+pacchetti.src+"\nSrcPort: "+str(pacchetti.payload.sport)+"\nDstPort: "+str(pacchetti.payload.dport)+"\nProtocol:"+str(pacchetti.proto)
                
                                                                                #Flag is an ascii value, if i do "Flag & 0x01" i can understand if the last bit is 0 or 1 
            if(Flag & SYN):                                                     #If thats true theres a new connection on the network
                plt.scatter(i, 7)
                plt.annotate(Str,xy=(i,7),xytext=(i+rnd, 7+rnd),arrowprops=dict(arrowstyle="->",connectionstyle="arc3"))
            elif(Flag & FIN):                                                   #If thats true one connection is "dead" or closed
                plt.scatter(i, 2)
                plt.annotate(Str,xy=(i,2),xytext=(i+rnd, 2+rnd),arrowprops=dict(arrowstyle="->",connectionstyle="arc3"))
            else:
                GraficcoFlag.append(0)
                plt.scatter(i, 0)

            plt.xlim([max(0,i-100),i+10])                                       #To create a dynamic graph with only updated data
            
            y=[0,2,7]
            Yname = ["","Closed Connection","Open Connection"]                                  #Replace Number with Word
            plt.yticks(y, Yname)
            plt.pause(0.001)                                                                    #Graph update

            c = cv.WaitKey(7) % 0x100
            if c == 27 or c == 10:
                break
            pass
        
        except KeyboardInterrupt:
            pass
        except:
            pass
    

    i = i+1
    return


####################################################################################
#Start Program
####################################################################################


pkts = sniff(offline=CaptureFileName ,prn=AnalyzePacket,store=0)             #Sniff packet one by one
                                                                                #pnr function is called for each packet

