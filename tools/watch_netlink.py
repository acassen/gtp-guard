#!/usr/bin/python3

from pyroute2 import IPRoute
from pprint import pprint

with IPRoute() as ipr:
    while True:
        ipr.bind()
        for message in ipr.get():
            pprint(message)
