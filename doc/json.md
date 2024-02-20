# JSON Monitoring RPC

A json monitoring RPC is available over TCP once it is enabled thanks to
the command:
```
!
pdn
  request-channel 127.0.0.1 port 8080
!
```

## Supported RPCs

Currently, only 1 RPC is supported.

### `imsi_info`

Request format:
```
{
  "cmd": "imsi_info",
  "apn": "your_apn",
  "imsi": "your_imsi"
}
```

The `imsi_info` command returns the following JSON output:
```
{
  "sgw-ip-address": "A.B.C.D"
}
```

## Errors

In the event of an error, the following JSON structure is returned:
```
{
  "Error": "error message"
}
```

The possible error messages include:
  - "No command specified": the `cmd` keyword is missing.
  - "Unknown command": the valud of `cmd` is not `imsi_info`.
  - "No Access-Point-Name specified": the `apn` value is missing.
  - "No IMSI specified": the `imsi` value is missing.
  - "Unknown Access-Point-Name": the `apn`'s value is not a recognized APN.
  - "Unknown IMSI": the `imsi` value is not a recognized IMSI.

## Example

The following Python script is designed to handle such JSON RPCs. You should customize
it according to your specific requirements:

```python
import socket
import sys
import json

jsonResult = {
  "cmd": "imsi_info",
  "apn": "your_apn",
  "imsi": "your_imsi"
}

jsonResult = json.dumps(jsonResult)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    sock.connect(("localhost", 8080))
    # do not forget the \r\n for each buffer
    sock.send(jsonResult.encode()+bytes("\r\n", "utf-8"))
    print("Sent: {}".format(jsonResult))

    received = sock.recv(1024)
    received = received.decode("utf-8")

finally:
    sock.close()

print("Received: {}".format(received))
```
