"""
network_stats.py
Copyright: jdchambo@bu.edu

Takes input from whitelist and/or blacklist statistics collected
in network monitoring, and prints to screen depending on user 
selections for what to display.

written in python 3.5.2
"""

# open files, write to data structure
"""
file data should be stored in following order (space delimited):
Source_IP Dest_IP Protocol DSCP_Precedence DSCP_delay DSCP_throughput DSCP_reliability DSCP_cost \n
"""

# while loop; select IP addr to report on (or cummulative stats)

# if specific IP, select items to report on:

"""
DestIP & resolved addr
Protocol num (TCP,UDP,TLS, or other)
DSCP field values (precedence, delay, throughput, reliability, cost)

"""



# if cummulative, report stats per source IP
'''
including resolved domain of source IP
'''
