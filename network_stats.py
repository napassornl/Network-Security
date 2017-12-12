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
  if values[2] == '56':
    # using TLS (HTTPS)
    summary[srcip]['HTTPS'] += 1
    detail[srcip][tarip]['HTTPS'] += 1
  elif (values[2] == '6' or values[2] == '17'):
    # using TCP or UDP (HTTP)
    summary[srcip]['HTTP'] += 1
    detail[srcip][tarip]['HTTP'] += 1
  else:
    # using some other protocol
    summary[srcip]['Other'] += 1
    detail[srcip][tarip]['Other'] += 1
  # Precendence
  if values[3] != '0':
    # Precedence is anything other than Routine
    detail[srcip][tarip]['non-routine'] += 1
  # Delay
  if values[4] == '1':
    # Low Delay is set
    detail[srcip][tarip]['low delay'] += 1
  # Throughput
  if values[5] == '1':
    # High Throughput is set
    detail[srcip][tarip]['high tp'] += 1
  # Reliability
  if values[6] == '1':
    # high reliability is set
    detail[srcip][tarip]['high reliable'] += 1 
  # Cost
  if values[7] == '1':
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
     s = str(tarip) + '|' + str(msg) + '|' + str(HTTPS/msg) + '|' + str(HTTP/msg) + '|' + str(Other/msg) + '|' + str(NR/msg) + '|' + str(LD/msg) + '|' + str(HT/msg) + '|' + str(HR/msg) + '|' + str(MC/msg)
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
# counters for messages encountered
bltotal = 0
wltotal = 0

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
      detail[srcip] = {}
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
    tarip = values[1]
    if values[0] not in whitelist:
      whitelist.append(values[0])
      summary[srcip] = {'msg': 0, 'HTTPS': 0, 'HTTP': 0, 'Other': 0}
      detail[srcip] = {}
    if tarip not in detail[srcip].keys():
      detail[srcip][tarip] = {'msg':0, 'HTTPS': 0, 'HTTP': 0, 'Other': 0, 'non-routine': 0, 'low delay': 0, 'high tp': 0, 'high reliable': 0, 'min cost': 0}
    # update dictionary values
    updates(srcip, tarip, values, summary, detail)
  # done reading, close file
  safe.close()

"""
Print cummulative statistics for blacklist, whitelist
"""

if (sys.argv[1] == 'B' or sys.argv[1] == 'A'):
  blHTTPS = 0
  blHTTP = 0
  blOthers = 0
  print("Statistics from blacklisted IPs\nSource IP|Source Host|# msgs|% HTTPS|% HTTP|% Other")
  for blsrcip in blacklist:
    try:
      blsrchst = socket.gethostbyaddr(blsrcip)[0]
    except:
      blsrchst = "Unknown Host"
    msg = summary[blsrcip]['msg']
    HTTPS = summary[blsrcip]['HTTPS']
    HTTP = summary[blsrcip]['HTTP']
    Other = summary[blsrcip]['Other']
    s = str(blsrcip) + '|' + str(blsrchst) + '|' + str(msg) + '|' + str(HTTPS/msg) + '|' + str(HTTP/msg) + '|' + str(Other/msg)
    print(s)
    bltotal += msg
    blHTTPS += HTTPS
    blHTTP += HTTP
    blOthers += Other
  if bltotal > 0:
    s = 'Total|' + str(bltotal) + '|' + str(blHTTPS/bltotal) + '|' + str(blHTTP/bltotal) + '|' + str(Other/bltotal)
    print(s)
  else:
    print('No Data in Range')
  print('\n')

if (sys.argv[1] == 'W' or sys.argv[1] == 'A'):
  wlHTTPS = 0
  wlHTTP = 0
  wlOthers = 0
  print("Statistics from whitelisted IPs\nSource IP|Source Host|# msgs|% HTTPS|% HTTP|% Other")
  for wlsrcip in whitelist:
    try:
      wlsrchst = socket.gethostbyaddr(wlsrcip)[0]
    except:
      wlsrchst = "Unknown Host"
    msg = summary[wlsrcip]['msg']
    HTTPS = summary[wlsrcip]['HTTPS']
    HTTP = summary[wlsrcip]['HTTP']
    Other = summary[wlsrcip]['Other']
    s = str(wlsrcip) + '|' + str(wlsrchst) + '|' + str(msg) + '|' + str(HTTPS/msg) + '|' + str(HTTP/msg) + '|' + str(Other/msg)
    print(s)
    wltotal += msg
    wlHTTPS += HTTPS
    wlHTTP += HTTP
    wlOthers += Other
  if wltotal > 0:
    s = 'Total|' + str(wltotal) + '|' + str(wlHTTPS/wltotal) + '|' + str(wlHTTP/wltotal) + '|' + str(Other/wltotal)
    print(s)
  else:
    print('No Data in Range\n')
  print('\n')

if (sys.argv[1] == 'A'):
  total = bltotal + wltotal
  allHTTPS = blHTTPS + wlHTTPS
  allHTTP = blHTTP + wlHTTP
  allOther = blOthers + wlOthers
  if total > 0:
    print("Overall totals\n")
    s = 'Total|' + str(total) + '|' + str(allHTTPS/total) + '|' + str(allHTTP/total) + '|' + str(allOther/total)
    print(s)
  print('\n')


"""
Assuming user entered valid input
Prompt user for specific IP to report additional statistics:
DestIP & resolved addr
Protocol num (TCP,UDP,TLS, or other)
DSCP field values (precedence, delay, throughput, reliability, cost)
"""

if (sys.argv[1] == 'A' or sys.argv[1] == 'B' or sys.argv[1] == 'W'):
  if (wltotal > 0 or bltotal > 0):
    while True:
      addr = input("Enter Target IP address for additional information, or Enter to exit:")
      if addr == '':
        break
      elif addr in blacklist:
        printdetails(addr, detail)
      elif addr in whitelist:
        printdetails(addr, detail)
      else:
        print("\nInvalid Target IP, please try again\n")
else:
  print("\nExpected Commandline Input of B for blacklisted IP stats, W for whitelisted IP stats, or A for all.\n")
  

