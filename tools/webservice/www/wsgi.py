# SPDX-License-Identifier: AGPL-3.0-or-later 
#
# Soft:        The main goal of gtp-guard is to provide robust and secure
#              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
#              widely used for data-plane in mobile core-network. gtp-guard
#              implements a set of 3 main frameworks:
#              A Proxy feature for data-plane tweaking, a Routing facility
#              to inter-connect and a Firewall feature for filtering,
#              rewriting and redirecting.
#
# Authors:     Alexandre Cassen, <acassen@gmail.com>
#
#              This program is free software; you can redistribute it and/or
#              modify it under the terms of the GNU Affero General Public
#              License Version 3.0 as published by the Free Software Foundation;
#              either version 3.0 of the License, or (at your option) any later
#              version.
#
# Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
#

"""Application entry point."""
import getopt
from app import create_app

#
#       Command line parsing
#
class CmdLine:
	def __init__(self, pname):
		self.pname = pname
		self.server = ''
		self.port = 5000
		self.debug = False

	def parse(self, argv):
		try:
			opts, args = getopt.getopt(argv,"hs:p:d",["server=","port="])
		except getopt.GetoptError:
			print( "%s -s <server> -p <port> -d" % self.pname)
			sys.exit(2)
		for opt, arg in opts:
			if opt == '-h':
				print("%s -s <server> -p <port> -d" % self.pname)
				sys.exit()
			elif opt == '-d':
				self.debug = True
			elif opt in ("-s", "--server"):
				self.server = arg
			elif opt in ("-p", "--port"):
				self.port = int(arg)

#
#	Main stuff
#
app = create_app()
if __name__ == "__main__":
#	cmd = CmdLine(sys.argv[0])
#	cmd.parse(sys.argv[1:])
#	app.run(host=cmd.server, port=cmd.port, debug=cmd.debug)
#	app.run(host="127.0.0.1", port=9200, debug=True)
#	app.run(debug=True)
	app.run()
