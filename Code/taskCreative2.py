import pandas as pd

from scapy .all import * # importing scapy library

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP

import matplotlib.pyplot  as plt
import numpy as np

CaptureFileName = "network_traffic.pcap"                                        #.pcap File name


i=0                                                                             #Flag counter (used in analyzePacketFunction)

traffic_ammount = 0
start_time=0
traffic_per_minute = []
intervallo = 1

plt.title("Total Traffic in the network ")
plt.xlabel("Time")
plt.ylabel("Traffic per second")

def AnalyzePacket(packet):
    global i
    global traffic_ammount
    global start_time   
    packet_time = round(packet.time,2)                                          #
                  
    for pacchetti in packet[IP]:                                                #For each packet it will extract task 1 information
        if  packet_time > start_time + intervallo:
            start_time = packet_time
            traffic_per_minute.append(traffic_ammount)
            traffic_ammount = 0
            plt.plot(traffic_per_minute,color="blue")
            plt.pause(0.01)
        else:
            traffic_ammount = traffic_ammount + pacchetti.len
  
    

    i = i+1
    return


####################################################################################
#Start Program
####################################################################################


pkts = sniff(offline=CaptureFileName ,prn=AnalyzePacket,store=0)                       #Sniff packet one by one
                                                                                #pnr function is called for each packet
plt.savefig('taskCreative3.png')
