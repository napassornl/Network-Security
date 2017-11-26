"""
Copyright napalerd@bu.edu

This script continuously parses a IP packet sent to the socket of the source, and compares
its IP header toith a white list consisting of BU's networks, and flags them
as safe if in the white list and unsafe otherwise. The result is printed in a file
in the following form (space delimited):

Source_IP Dest_IP Protocol DSCP_Precedence DSCP_delay DSCP_throughput DSCP_reliability DSCP_cost \n

For parsing a IP packet, there are functions to parse for the transport protocol type and
DSCP. The IP packet is stored as an IPv4 address object (assuming all packets are version 4).

written in python 3.5.2
"""

# Need to run program through Admin command line
import socket
import sys
import struct
import re # regular expression
import ipaddress
import time

"""The goal of this function is to obtain the IP packet from the socket. The data
is in a tuple form, ie. (b'E\x00\x00)b-@\x00\x80\x06\xde\xb9\x9b)!\xa24,\xc8\xf0\xcb\x9d\x01\xbbE
# \xf4\xc2^\xf9\xd3\xcd\xfbP\x10\x00\xfbWu\x00\x00\x00', ('155.41.33.162', 0))"""
def receiveData(s):
    data = ''
    try:
        data = s.recvfrom(65565) # biggest length capacity
    except timeout:
        data = ''
    except:
        print("Error happened")
        sys.exc_info()
    return data[0] # get first element of tuple

"""The goal of thios function is to parse for the differentiated services (DSCP)
and precedence values from the IP header for packet classification"""
def getTOS(data): # 8 bits
    # write dictionary of what each bit means according to website
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash",
     4: "FlashOverride", 5: "CRITIC/ECP", 6: "InternetworkControl",
      7: "NetworkControl"}
    delay = {0:"NormalDelay", 1:"LowDelay"}
    throughput = {0: "NormalThroughput", 1: "HighThroughput"}
    reliability = {0: "NormalReliability", 1: "HighReliability"}
    cost = {0: "NormalCost", 1: "MinimizeCost"}

    D = data & 0x10
    D >> 4 # bitwise operator shifts to right by n bits
    T = data & 0x8
    T>>3
    R = data & 0x4
    R >>2
    M = data & 0x2
    M >>1

    try:
        TOS = precedence[data >> 5] + " " + delay[D] + " " + throughput[T] + " " + reliability[R] + " " + cost[M]
    except:
        TOS = "N/A" + " " + "N/A" + " " + "N/A" + " " + "N/A" + " " + "N/A"
    return TOS

"""The goal of this function is to parse for the type of transport Layer
 protocol. A list of all types of protocols are stored in the Protocol.txt files.
 The function searches the file for a match."""
def getProtocol(protocolNo):
    protocolFile = open("Protocol.txt", "r")
    protocolData = protocolFile.read()
    # usign regular expression format
    protocol = re.findall(r"\n" + str(protocolNo)+ "(.*)" + "\n", protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace("\n","")
        protocol = protocol.replace(str(protocolNo),"")
        protocol = protocol.replace(" ","")
        protocol = protocol.replace(".","")
        protocol = protocol.lstrip()

        return protocol
    else:
        return "N/A"


# the public network interface
HOST = socket.gethostbyname(socket.gethostname())

try:
    while True:
        # create a raw socket and bind it to the public interface
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((HOST, 0))

        # Include IP headers
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # receive all packages
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        print("Monitoring ...")

        # receive a package from socket
        data = receiveData(s)
        # unpack ip header in this form
        unpackedData = struct.unpack('!BBHHHBBH4s4s' , data[:20])

        # # parse ip header - 32 bits long
        TOS = unpackedData[1]
        #ID = unpackedData[3]
        protocolNo = unpackedData[6]
        sourceAddress = socket.inet_ntoa(unpackedData[8]) # converts IPv4 address to 32-bit pack binary format
        destAddress = socket.inet_ntoa(unpackedData[9])
        IPv4source = ipaddress.ip_address(sourceAddress) # IPv4address object
        IPv4dest = ipaddress.ip_address(destAddress)

        # open the whitelist
        wl = open('WHITELIST.txt',"r")
        white = wl.readlines()
        whiteList = []

        # store whiteList networks in array - assuming all are networks
        for i in range(len(white)):
             whiteList.append(white[i].strip('\n'))

        wl.close()

        # create safe and unsafe files
        safe = open('SAFEPACKETS.txt', "a")
        unsafe = open('UNSAFEPACKETS.txt', "a")

        for net in whiteList:
        # check incoming packets to whitelist
            if IPv4source in ipaddress.ip_network(net):
                print(str(IPv4source) + " is safe.")
                safe.write(str(IPv4source)+ " " +str(IPv4dest)+ " " +getProtocol(protocolNo)+ " "+str(getTOS(TOS)) + "\n" )
                break
            if net == whiteList[len(whiteList)-1]:
                print(str(IPv4source) + " is not safe.")
                unsafe.write(str(IPv4source)+ " " +str(IPv4dest)+ " " +getProtocol(protocolNo)+ " "+str(getTOS(TOS)) + "\n" )

        # disabled promiscuous mode
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print(" ")

except KeyboardInterrupt:
    pass
