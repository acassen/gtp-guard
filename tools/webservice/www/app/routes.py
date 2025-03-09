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

import socket
import sys
import json
from flask import current_app as app
from flask import redirect, url_for, request, jsonify


#
#	GTP-Guard related
#
class gtpguard:
	def __init__(self):
		self.sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sd.settimeout(30)

	def sendJSON(self, addr_ip, addr_port, json_post):
		try:
			self.sd.connect((addr_ip, addr_port))
		except socket.error as msg:
			return ''

		try:
			self.sd.sendall(json_post)
			self.sd.sendall(b'\r\n')
		except socket.error as msg:
			self.sd.close()

	def recvJSON(self):
		json_data = ''
		gtp_json_resp = ''
		try:
			while True:
				chunk = self.sd.recv(2048)
				if len(chunk) <= 0:
					break
				gtp_json_resp += chunk.decode("utf-8")
		except socket.error as msg:
			self.sd.close()
		finally:
			json_data = json.loads(gtp_json_resp)
			self.sd.close()
			return json_data

#
#	Routes declarations
#
gtp_addr_ip = '127.0.0.1'
gtp_addr_port = 1665
granted_cmd = ['imsi_info']
@app.route("/gtpWS", methods=['POST'])
def gtpWS():
	granted = False
	content = request.json
	for cmd in granted_cmd:
		if content['cmd'] == cmd:
			granted = True
			break
	if not granted:
		return jsonify({"Error": "Unauthorized command"})

	# Filter out debug option
	for element in content:
		if 'enable_debug_json' in element:
			del content['enable_debug_json']
			break
	new_req = json.dumps(content)
	json_obj = bytes(new_req, encoding="utf-8")

	gtp = gtpguard()
	gtp.sendJSON(gtp_addr_ip, gtp_addr_port, json_obj)
	json_data = gtp.recvJSON()
	return jsonify(json_data)
