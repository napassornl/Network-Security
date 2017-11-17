"""
Copyright napalerd@bu.edu

This script parses a message sent to the socket of the source, and compares
its IP packet with a white list consisting of BU's networks, and flags them
as safe if in the white list and unsafe otherwise.

For parsing a message, the information is printe and its IP packet is stored as
an IPv4 address object. The script reads the whitelist and stores the elements
in an array of strings. To compare if an incoming packet is safe, the script
converts each string element to an IPv4 network object.

This is assuming that the whitelist consists of only network address or IP
address range, but will need to account for individual IP addresses as well.

written in python 3.5.2
"""

# Need to run program through Admin command line
import socket
import sys
import struct
import re # regular expression
import ipaddress


# receive data from socket
# data is tuple
# ie. (b'E\x00\x00)b-@\x00\x80\x06\xde\xb9\x9b)!\xa24,\xc8\xf0\xcb\x9d\x01\xbbE
# \xf4\xc2^\xf9\xd3\xcd\xfbP\x10\x00\xfbWu\x00\x00\x00', ('155.41.33.162', 0))
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

# get type of Services TOS
def getTOS(data): # 8 bits
    # write dictionary of what each bit means according to website
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash",
     4: "Flash override", 5: "CRITIC/ECP", 6: "Internetwork control",
      7: "Network control"}
    delay = {0:"Normal delay", 1:"Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal cost", 1: "Minimize cost"}

    D = data & 0x10
    D >> 4 # bitwise operator shifts to right by n bits
    T = data & 0x8
    T>>3
    R = data & 0x4
    R >>2
    M = data & 0x2
    M >>1

    tabs = '\n\t\t\t'
    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] +tabs + cost[M]
    return TOS

# get flags
def getFlags(data):
    flagsR = {0: "0 - Reserved Bit"}
    flagsDF = {0: "0 - Fragment if necessary", 1: "1 - Do not Fragment"}
    flagsMore = {0: "0 - This is the last fragment", 1: "1 - More fragments follow this fragment"}

    R = data & 0x8000
    R >> 15
    DF = data & 0x4000
    DF >> 14
    MF = data & 0x2000
    MF >> 13

    tabs = "\n\t\t\t"
    flags = flagsR[R] + tabs + flagsDF[DF] + flagsMore[MF]
    return flags

def getProtocol(protocolNo):
    protocolFile = open("Protocol.txt", "r")
    protocolData = protocolFile.read()
    # regular exressions - not right
    protocol = re.findall(r"\n" + str(protocolNo)+ "(.*)" + "\n", protocolData)
    # protocol = re.findall(str(protocolNo), protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace("\n","")
        protocol = protocol.replace(str(protocolNo),"")
        protocol = protocol.lstrip()
        return protocol
    else:
        return "No such protocol was found"


# the public network interface
HOST = socket.gethostbyname(socket.gethostname())

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# receive a package from socket
data = receiveData(s)
# unpack ip header
unpackedData = struct.unpack('!BBHHHBBH4s4s' , data[:20])
#print(unpackedData)
# B size is 1 byte = 8 bits - gets Version + Internet Header Length +Services
# H size is 2 bytes = 16 bits - gets total length

# parse ip header - 32 bits long
version_IHL = unpackedData[0]
#print(version_IHL)
version = version_IHL >> 4 # shifts by 4 to get version - ip = 4
# print(version)
IHL = version_IHL & 0xF # min values is 5 ; 0xF is hexidecimal
# print(IHL)
TOS = unpackedData[1]
totalLength = unpackedData[2]
ID = unpackedData[3]
flags = unpackedData[4]
fragmentOffset = unpackedData[4] & 0x1FF
# get time to leave
TTL = unpackedData[5]
protocolNo = unpackedData[6]
checksum = unpackedData[7]
sourceAddress = socket.inet_ntoa(unpackedData[8]) # converts IPv4 address to 32-bit pack binary format
destAddress = socket.inet_ntoa(unpackedData[9])

print("An IP packet with size %i was captured" % (totalLength))
print("Raw Data: " + str(data))
print("\nParsed data: ")
print("Version: \t\t" + str(version))
print("Header Length:\t\t" + str(IHL*4) + " bytes")
print("Type of Service:\t" + str(getTOS(TOS)))
print("Length:\t\t\t" + str(totalLength))
print("ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ") ")
#print("Flags:\t\t\t" + str(getFlags(flags)))
print("Fragment offset:\t" + str(fragmentOffset))
print("TTL:\t\t\t" + str(TTL))
print("Protocol:\t\t" + getProtocol(protocolNo))
print("Checksum:\t\t" + str(checksum))
print("Source:\t\t\t" + sourceAddress)
print("Destination:\t\t" + destAddress)
#print("Payload:\n" + str(hex(data[20:])))

# IPv4Address object
print("*****************************************************")
print("")
print("Data from IPv4 objects: ")

IPv4source = ipaddress.ip_address(sourceAddress) # IPv4address object
IPv4dest = ipaddress.ip_address(destAddress)
print("Version: \t\t" + str(IPv4source.version))
print("Source:\t\t\t" + str(IPv4source))
print("Destination:\t\t" + str(IPv4dest))
sourceNetwork = ipaddress.IPv4Network(str(IPv4source))
print("Source's network: \t" + sourceNetwork.with_netmask)
destNetwork = ipaddress.IPv4Network(str(IPv4dest))
print("Destination's network: \t" + destNetwork.with_netmask)
# print("Total addresses in dest network: "+ str(destNetwork.num_addresses))
# shosts = list(destNetwork.hosts())
# print ("Source hosts: ")
# for host in shosts:
#     print("\t\t\t" + int(host))


print("********************************************")
# open the whitelist to compare packets
wl = open('WHITELIST.txt',"r")
white = wl.readlines()
whiteList = []

# store whiteList networks in array - assuming all are networks
print("The whitelist consists of: ")
for i in range(len(white)):
    print(white[i].strip('\n'))
    whiteList.append(white[i].strip('\n'))

print("")

for net in whiteList:
# check incoming packets
    if IPv4dest in ipaddress.ip_network(net):
        print(str(IPv4dest) + " is safe.")
        break
    if net == whiteList[len(whiteList)-1]:
        print(str(IPv4dest) + " is flagged as not safe.")

# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
