# GTP Guard Webservice

GTP-Guard provides a built-in JSON listener feature. This channel is specifically designed to interact
remotely with others piece of software for integration into tools such as monitoring or any provisioning
system.

The goal is not to include and integrate any HTTP or web server directly into the GTP Guard daemon,
instead we are relying on a regular web server like nginx in our example here. The webserver will then
interact directly with the GTP-Guard daemon via a private and local connection to protect and prevent
any direct access to the GTP-Guard daemon from the outside. We can then use the full feature set of the
webserver to protect and control access.

Here is a quick-start guide on how to simply enable this webservice feature.

## Content of this repository

Webservice works via gunicorn directly integrated into nginx via wsgi. The following elements are present
in the current repository :

* nginx-gtp-guard : nginx configuration sample
* systemd-gtp-guard-WS.service : systemd gunicorn service
* www : webservice itself interacting with GTP-Guard

## System packages required

We assume Ubuntu system is used, then the following package need to be installed :
```
$ sudo apt install nginx gunicorn python3-flask
```

## Webservice configuration

We are using SSL in our nginx configration : you can generate self-signed certificate using the
following command line :
```
openssl req -x509 -nodes -days 36500 -newkey rsa:2048 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.crt
```

you need to create www document-root, log and copy webservice :
```
$ sudo mkdir /var/www/gtp-guard
$ sudo mkdir /var/log/nginx/gtp-guard
$ sudo cp -r www/* /var/www/gtp-guard/
$ sudo cp nginx-gtp-guard /etc/nginx/sites-enabled
$ sudo ln -s /etc/nginx/sites-available/gtp-guard /etc/nginx/sites-enabled/
$ sudo systemctl restart nginx
```

## Gunicorn service configuration

Nginx will interact with gunicorn to provide webservice, you need to install and enable systemd
related :
```
$ sudo cp systemd-gtp-guard-WS.service /etc/systemd/system/gtp-guard-WS.service
$ sudo cd /etc/systemd/system
$ sudo systemctl enable gtp-guard-WS.service
$ sudo systemctl start gtp-guard-WS.service
```

## GTP-Guard configuration

Request channel need to be configured in GTP-Guard daemon in pdn section:
```
!
! GTP Guard configuration saved from vty
!   2025/01/29 15:14:31
!
hostname gtp-guard
!
pdn
 request-channel 127.0.0.1 port 1665
...
```

## Testing it !

Our webserver is listening on 10.0.0.254:443 :
```
curl -k --header "Content-Type: application/json" --request POST \
        --data '{"cmd":"imsi_info"}' https://10.0.0.254/gtpWS
```

