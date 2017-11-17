""""
Copyright jdchambo@bu.edu

Gets input from user, in form of CIDR blocks, to use to generate whitelist
for network monitoring. After receiving input, checks that address represents a
valid network, and if so writes the text value to a file to be loaded from when
the monitor is initialized.

The user may specify a custom whitelist file, in order to be able to maintain
separate whitelists (for separate networks, or for testing purposes). By default
whitelist behavior is to append to existing file to avoid overwriting previous list
entries.

written in python 3.5.2
"""
import ipaddress
import sys

if len(sys.argv) > 1:
  wlname = sys.argv[1] #assume first arg is the file name
else:
  wlname = 'WHITELIST.txt' #default whiltelist

# open the whitelist - append to existing list
wl = open(wlname,"a")

print("Enter networks to be added to whitelist in CIDR IPv4/prefix format")
print("(e.g. 128.128.0.0/16)")
print("A single address can be added by omitting the prefix")
print("Press the Enter key on a new line to exit")

# Loop through and add user entries to whitelist (if valid)
while True:
  addr = input("Enter next network: ")
  if addr == '':
      break
  try:
      faddr = ipaddress.IPv4Network(addr)
  except ipaddress.AddressValueError:
      print("Invalid Address - must be valid IPv4 address in a.b.c.d format")
  except ipaddress.NetmaskValueError:
      print("Invalid Netmask - must be integer between 1 and 32")
  except ValueError:
      print("Invalid Address - host bits set, recheck entry")
  else:
      wl.write(addr+'\n')


# done reading, close open file
wl.close();
