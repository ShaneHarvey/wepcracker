import os
import re
from subprocess import Popen, PIPE
from interface import Interface


__author__ = 'michael'

def iwconfig():
    lst = []
    tmpiface = Interface(None, None, None, None)

    cmd = Popen(['iwconfig'], stdout=PIPE, stderr=devnull)
    for line in cmd.communicate()[0].split('\n\n'):
        line = line.strip()

        if len(line) == 0:
            continue

        ifname = re.search('^([A-Za-z0-9]+)', line)
        ifessid = re.search('ESSID:"([A-Za-z0-9]+)"', line)
        ifmode = re.search('Mode:([A-Za-z]+)', line)
        ifbssid = re.search('Access Point: ([0-9:A-F]+)', line)

        if ifname is not None and ifessid is not None and ifmode is not None and ifbssid is not None:
            lst.append(Interface(ifname.group(1), ifessid.group(1), ifmode.group(1), ifbssid.group(1)))
            print ifname.group(1)
            print ifessid.group(1)
            print ifmode.group(1)
            print ifbssid.group(1)

        return lst

devnull = open(os.devnull, 'w')
iwconfig()

devnull.close()
