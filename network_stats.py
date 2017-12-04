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
define functions to process data
"""

def updates(srcip, tarip, values, summary, detail):
  """
  update dictionary values based on input from values
  scrip, tarip - strings containing Source, Target IP from packet
  values - list of paramters for options in IP packet header
  summary, detail - dictionaries
  """
  # increase message count
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
    # High Throughput is set
    detail[srcip][tarip]['high tp'] += 1
  # Reliability
  if values[6] == 1:
    # high reliability is set
    detail[srcip][tarip]['high reliable'] += 1 
  # Cost
  if values[7] == 1:
    # minimum cost is set
    detail[srcip][tarip]['min cost'] += 1


def printdetails(ipaddr, detail):
   """
   print detailed information for the specified ipaddress
   ipaddr - user supplied source IP address
   detail - dictionary with stats
   """
   print("Target IP|# msgs|% HTTPS|% HTTP|% Other|% Non Routine|% Low Delay|% High Throughput|% High Reliability|% Minimize Cost\n")
   for tarip in detail[ipaddr].keys():
     msg = detail[ipaddr][tarip]['msg']
     HTTPS = detail[ipaddr][tarip]['HTTPS']
     HTTP = detail[ipaddr][tarip]['HTTP']
     Other = detail[ipaddr][tarip]['Other']
     NR = detail[ipaddr][tarip]['non-routine']
     LD = detail[ipaddr][tarip]['low delay']
     HT = detail[ipaddr][tarip]['high tp']
     HR = detail[ipaddr][tarip]['high reliable']
     MC = detail[ipaddr][tarip]['min cost']
     s = tarip + '|' + msg + '|' + HTTPS/msg + '|' + HTTP/msg + '|' + Other/msg + '|' + NR/msg + '|' + LD/msg + '|' + HT/msg + '|' + HR/msg + '|' + MC/msg
     print(s)
   print('\n')

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
    updates(srcip, tarip, values, summary, detail)
  # done reading, close file
  unsafe.close()

if (sys.argv[1] == 'W' or sys.argv[1] == 'A'):
  # open whitelist file
  safe = open('SAFEPACKETS.txt',"r")
  # loop through and store in structs
  for line in safe.readlines():
    values = line.split()
    srcip = values[0]
    tarip = values[0]
    if values[0] not in whitelist:
      whitelist.append(values[0])
      summary[srcip] = {'msg': 0, 'HTTPS': 0, 'HTTP': 0, 'Other': 0}
    if tarip not in detail[srcip].keys():
      detail[srcip][tarip] = {'msg':0, 'HTTPS': 0, 'HTTP': 0, 'Other': 0, 'non-routine': 0, 'low delay': 0, 'high tp': 0, 'high reliable': 0, 'min cost': 0}
    # update dictionary values
    updates(srcip, tarip, values, summary, detail)
  # done reading, close file
  safe.close()

"""
Print cummulative statistics for blacklist, whitelist
"""

if (sys.argv[1] == 'B'):
  bltotal = 0;
  blHTTPS = 0;
  blHTTP = 0;
  blOthers = 0;
  print("Statistics from blacklisted IPs\nSource IP|Source Host|# msgs|% HTTPS|% HTTP|% Other")
  for blsrcip in blacklist:
    blsrchst = socket.gethostbyaddr(blsrcip)
    msg = summary[blsrcip]['msg']
    HTTPS = summary[blsrcip]['HTTPS']
    HTTP = summary[blsrcip]['HTTP']
    Other = summary[blsrcip]['Other']
    s = blscrip + '|' + blsrchst + '|' + msg + '|' + HTTPS/msg + '|' + HTTP/msg + '|' + Other/msg
    print(s)
    bltotal += msg
    blHTTPS += HTTPS
    blHTTP += HTTP
    blOthers += Other
  s = 'Total|' + bltotal + '|' + blHTTPS/bltotal + '|' blHTTP/msg + '|' + Other/msg
  print(s)
  print('\n')

if (sys.argv[1] == 'W'):
  wltotal = 0;
  wlHTTPS = 0;
  wlHTTP = 0;
  wlOthers = 0;
  print("Statistics from whitelisted IPs\nSource IP|Source Host|# msgs|% HTTPS|% HTTP|% Other")
  for wlsrcip in whitelist:
    wlsrchst = socket.gethostbyaddr(wlsrcip)
    msg = summary[wlsrcip]['msg']
    HTTPS = summary[wlsrcip]['HTTPS']
    HTTP = summary[wlsrcip]['HTTP']
    Other = summary[wlsrcip]['Other']
    s = wlscrip + '|' + wlsrchst + '|' + msg + '|' + HTTPS/msg + '|' + HTTP/msg + '|' + Other/msg
    print(s)
    wltotal += msg
    wlHTTPS += HTTPS
    wlHTTP += HTTP
    wlOthers += Other
  s = 'Total|' + wltotal + '|' + wlHTTPS/bltotal + '|' wlHTTP/msg + '|' + Other/msg
  print(s)
  print('\n')

if (sys.argv[1] == 'A'):
  total = bltotal + wltotal
  allHTTPS = blHTTPS + wlHTTPS
  allHTTP = blHTTP + wlHTTP
  allOther = blOthers + wlOthers
  print("Overall totals\n")
  s = 'Total|' + total + '|' + allHTTPS/total + '|' + allHTTP/total + '|' + allOther/total
  print(s)
  print('\n')


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
    printdetails(addr, detail)
  elif addr in whitelist:
    printdetails(addr, detail)
  else:
    print("\nInvalid input, please try again\n")
  

