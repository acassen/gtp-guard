#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Author: Vincent Jardin, <vjardin@free.fr>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Affero General Public
# License Version 3.0 as published by the Free Software Foundation;
# either version 3.0 of the License, or (at your option) any later
# version.
#
# Copyright (C) 2025 Vincent Jardin, <vjardin@free.fr>

import json
import socket

class CommandClient:
    """
    Base class to handle all low-level socket interactions and JSON communication
    with gtp-guard.
    Derived classes can call _send_command to perform custom commands.

    assuming gtp-guard.conf with:
    !
    pdn
      request-channel 127.0.0.1 port 8080
    !
    """
    def __init__(self, host='localhost', port=8080):
        self.host = host
        self.port = port

    def _send_command(self, cmd, **kwargs):
        """
        Internal helper method to send the command + data over
        a TCP connection and return the server response.

        :param cmd: The command string (e.g., 'imsi_info')
        :param kwargs: Additional key-value pairs to include in the JSON.
        :return: Tuple of (raw_response_string, parsed_json_or_None)
        """
        message_dict = {"cmd": cmd}
        message_dict.update(kwargs)  # Merge additional kwargs
        message = json.dumps(message_dict) + "\r\n"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            sock.sendall(message.encode('utf-8'))
            # print(f"Debug, Sent: {message.strip()}")

            response_chunks = []
            # read all the buffer until no more data for closed by the server
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_chunks.append(chunk)
                except ConnectionResetError:
                    break

            response = b''.join(response_chunks).decode('utf-8')

        try:
            parsed_json = json.loads(response)
            # print("Debug: Received (pretty JSON):")
            # print(json.dumps(parsed_json, indent=2))
            return response, parsed_json
        except json.JSONDecodeError:
            # print("Debug: Received (raw text):")
            # print(response.strip())
            return response, None

class GtpGuardCommandsClient(CommandClient):
    """
    Derived class that adds custom command methods on top of CommandClient.
    Each method calls the inherited _send_command() from the base class.
    """
    def imsi_info(self, apn, imsi):
        """
        Send an 'imsi_info' command.

        :param apn: The APN string
        :param imsi: The IMSI string
        :return: Tuple of (raw_response_string, parsed_json_or_None)
        """
        return self._send_command('imsi_info', apn=apn, imsi=imsi)

    def get_status(self):
        """
        XXX TODO Send a 'get_status' command.

        :return: Tuple of (raw_response_string, parsed_json_or_None)
        """
        return self._send_command('get_status')

if __name__ == "__main__":
    client = GtpGuardCommandsClient(host="localhost", port=8080)

    # example, set 'my_apn' and 'my_imsi'
    response_str, response_json = client.imsi_info("my_apn", "my_imsi")

    # response_str, response_json = client.get_status()
    if response_json is not None:
        print(json.dumps(response_json, indent=2))
    else:
        print(response_str)
