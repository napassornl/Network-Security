# Network Security Program
This is a group project for the Computer Networking class. The project aims to enhance user protection by creating a Python Network Security program to detect and monitors incoming data packets and flags unsecured packets from reaching computer host.  

The **whitelist.py program** obtains input IP networks from user, in form of CIDR (Classless Inter-Domain Routing) blocks, to generate a whitelist for network monitoring. After receiving these inputs, it checks that each address represents a valid network. If it does, the program writes the text value to a file to be loaded from when the **network_monitor.py program** is initialized.  

The user may specify a custom whitelist file, in order to be able to maintain separate whitelists (for separate networks, or for testing purposes). By default, new valid networks will be appended to the existing whitelist file to avoid overwriting previous list entries.  

Next, the **network_monitor.py program** opens the text file created in the **whitelist.py program** and makes each element in the file a IPv4 Network which consists of IPv4 address objects. There may be many IPv4 Network objects so they are all stored in an array.  

When our host receives a data packet from the internet, the network monitor program:  

1) Continuously catches IP packets arriving in the socket,  
2) Parses the IP headers to obtain relevant information including Source IP address, Destination IP address, Transport Protocol, DSCP (Differentiated Services) - delay, throughput, reliability, cost - and Precedence values,  
3) Checks whether the IP address matches those generated in the whitelist. If there is a match, the packet information is stored in a file called "SAFE.txt" and the unsafe packets are stored in another file called "UNSAFE.txt",  
4) The program will also print whether the packets are unsafe or safe on the console.  

The **network_stats.py program** reads in the information from whitelist file, "SAFE.txt", and/or blacklist file, "UNSAFE.txt", created by the **network_monitor.py program**, and prints to the screen depending on user selections for what to display. Specifically, the program prompts the user to enter "W" for whitelist reporting, "B" for blacklist reporting, or "A" for reporting on all.   
