"""
network_stats.py
Copyright: jdchambo@bu.edu

Takes input from whitelist and/or blacklist statistics collected
in network monitoring, and prints to screen depending on user 
selections for what to display.

Expects user to enter W for whitelist reporting, B for blacklist
reporting, or A for reporting on all

written in python 3.5.2
"""
import sys
import socket

"""
Open files and read into structures
file data stored as space delimited list:
Source_IP Dest_IP Protocol DSCP_Precedence DSCP_delay DSCP_throughput DSCP_reliability DSCP_cost 
"""

# lists of IPs
blacklist = []
whitelist = []
# dictionaries to hold data
summary = {}
detail = {}

if (sys.argv[1] == 'B' or sys.argv[1] == 'A'):
  # open blacklist file
  unsafe = open('UNSAFEPACKETS.txt',"r")
  # loop through and store in structs
  for line in unsafe.readlines():
    values = line.split()
    srcip = values[0]
    tarip = values[1]
    if srcip not in blacklist:
      blacklist.append(values[0])
      summary[srcip] = {'msg': 0, 'HTTPS': 0, 'HTTP': 0, 'Other': 0}
    if tarip not in detail[srcip].keys():
      detail[srcip][tarip] = {'msg':0, 'HTTPS': 0, 'HTTP': 0, 'Other': 0, 'non-routine': 0, 'low delay': 0, 'high tp': 0, 'high reliable': 0, 'min cost': 0}
    # update dictionary values
    summary[srcip]['msg'] += 1
    detail[srcip][tarip]['msg'] += 1
    # protocol
    if values[2] == 56:
      # using TLS (HTTPS)
      summary[srcip]['HTTPS'] += 1
      detail[srcip][tarip]['HTTPS'] += 1
    elif (values[2] == 6 or values[2] == 17):
      # using TCP or UDP (HTTP)
      summary[srcip]['HTTP'] += 1
      detail[srcip][tarip]['HTTP'] += 1
    else:
      # using some other protocol
      summary[srcip]['Other'] += 1
      detail[srcip][tarip]['Other'] += 1
    # Precendence
    if values[3] != 0:
      # Precedence is anything other than Routine
      detail[srcip][tarip]['non-routine'] += 1
    # Delay
    if values[4] == 1:
      # Low Delay is set
      detail[srcip][tarip]['low delay'] += 1
    # Throughput
    if values[5] == 1:
      detail[srcip][tarip][''] += 1
    # Reliability
    if values[6]
    # Cost
    if values[7]
  # done reading,
  # done reading, close file
  unsafe.close()

if (sys.argv[1] == 'W' or sys.argv[1] == 'A'):
  # open whitelist file
  safe = open('SAFEPACKETS.txt',"r")
  # loop through and store in structs
  for line in safe.readlines():
    values = line.split()
    srcip = values[0]
    tarip = values[
    if values[0] not in whitelist:
      whitelist.append(values[0])
      
    # update dictionary values
    # protocol
    if values[2] 
    # Precendence
    if values[3]
    # Delay
    if values[4]
    # Throughput
    if values[5]
    # Reliability
    if values[6]
    # Cost
    if values[7]
  # done reading, close file
  safe.close()

"""
Print cummulative statistics for blacklist, whitelist
"""

if (sys.argv[1] == 'B'):
  print("Statistics from blacklisted IPs\n")

if (sys.argv[1] == 'W'):
  print("Statistics from whitelisted IPs\n")

if (sys.argv[1] == 'A'):


"""
Prompt user for specific IP to report additional statistics:
DestIP & resolved addr
Protocol num (TCP,UDP,TLS, or other)
DSCP field values (precedence, delay, throughput, reliability, cost)
"""

while True
  addr = input("Enter IP address for additional information, or Enter to exit:")
  if addr == '':
    break
  elif addr in blacklist:
    print("Target IP|# msgs|% HTTPS|% HTTP|% Other|% Non Routine|% Low Delay|% High Throughput|% High Reliability|% Minimize Cost\n")
  elif addr in whitelist:
    print("Target IP|# msgs|% HTTPS|% HTTP|% Other|% Non Routine|% Low Delay|% High Throughput|% High Reliability|% Minimize Cost\n")
  else:
    print("\nInvalid input, please try again\n")
  

