#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# vim:fenc=utf-8

__author__ = 'Vincent Jardin'
__license__ = 'Distributed under terms of the AGPLv3 license.'
__copyright__ = 'Copyright (C) 2024 Vicnent Jardin. All rights reserved.'

from sys import argv, exit
from os import path
from scapy.all import *
from scapy.contrib.gtp import *

def gtpu_ping(host):
    ''' GTPu Ping - echo request '''

    resp = sr1(IP(dst=host)/UDP(sport=2152, dport=2152) / GTP_U_Header(teid=0x20100, gtp_type="echo_request"),
            timeout=1)

    if resp == None:
        sys.exit("GTPu echo request failed")

    print("GTPu echo request OK")

if __name__ == '__main__':
    gtpu_ping(sys.argv[1])
