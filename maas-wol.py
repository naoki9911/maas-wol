#!/usr/bin/env python3
#
# maas-wol - Web server to accept WoL requests
#
# Author: Lee Trager <lee.trager@canonical.com>
#
# Copyright (C) 2021 Canonical
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# thanks to https://gist.github.com/ltrager/8f5b0018914b2368920b8847f332b9f0

import argparse
import base64
import http.server
import socketserver
import signal
import logging
import sys
import socket
import re
import select
import json
import subprocess
import time
import threading


GET_REGEX = re.compile(r"^/(?P<MAC>([\da-f]{2}[:-]){5}[\da-f]{2})[/]?$", re.I)
POST_REGEX = re.compile(
    r"^/(?P<MAC>([\da-f]{2}[:-]){5}[\da-f]{2})/\?op=(?P<OP>(start|stop))$", re.I
)

# Dictionary containing machine statuses based on previous requests.
machine_status = {}
mac_to_ip = {}

def update_mac_to_ip(force=False):
    global mac_to_ip
    res = subprocess.check_output(["arp-scan", "192.168.150.0/24"])
    ips = res.decode('utf-8').split("\n")
    new_mac_to_ip = {}
    for ip_e in ips:
        cols = ip_e.split("\t")
        if len(cols) < 2:
            continue
        ip = cols[0]
        mac = cols[1]
        new_mac_to_ip[mac] = ip
    print("mac_to_ip updated")

    mac_to_ip = new_mac_to_ip
    print(mac_to_ip)

def get_ip_from_mac(mac_address):
    global mac_to_ip

    if mac_address in mac_to_ip:
        return mac_to_ip[mac_address]

    return None

def update_mac_to_ip_timer():
    while(True):
        try:
            update_mac_to_ip()
        except:
            continue
        time.sleep(15)

t = threading.Thread(target = update_mac_to_ip_timer)
t.start()

# User settings
broadcast_ip = None
broadcast_port = None
username = None
password = None
token = None


class HTTPWoL(http.server.SimpleHTTPRequestHandler):
    def _authenticate(self):
        global username, password, token
        if not username and not password and not token:
            return True
        try:
            cred = self.headers.get("Authorization").split()[1]
        except (IndexError, AttributeError):
            cred = None

        if token:
            # RFC 6750
            if cred == token:
                return True
        elif username or password:
            # RFC 7617
            if base64.b64decode(cred).decode() == f"{username}:{password}":
                return True
        else:
            self.send_response(http.client.UNAUTHORIZED)
            self.end_headers()
            self.wfile.write(b"Unauthorized!\n")
            return False

    def _bad_path(self):
        self.send_response(http.client.BAD_REQUEST)
        self.end_headers()
        self.wfile.write(b"Unknown path!\n")

    def do_GET(self):
        if not self._authenticate():
            return
        # MAAS will send the the system_id in the header
        # system_id = self.headers.get("System_id")
        m = GET_REGEX.search(self.path)
        if m:
            global machine_status
            mac_address = m.group("MAC")
            ip = get_ip_from_mac(mac_address)
            self.send_response(http.client.OK)
            self.end_headers()
            if ip == None:
                self.wfile.write(
                    json.dumps(
                        {"status": machine_status.get(m.group("MAC"), "stopped")}
                    ).encode()
                    + b"\n"
                )
            else:
                self.wfile.write(
                    json.dumps(
                        {"status": machine_status.get(m.group("MAC"), "running")}
                    ).encode()
                    + b"\n"
                )
        else:
            self._bad_path()

    def _start(self, mac_address):
        global machine_status, broadcast_ip, broadcast_port
        try:
            res = subprocess.check_output(["wakeonlan", mac_address])
            self.send_response(http.client.OK)
            self.end_headers()
            self.wfile.write(b"WoL packet sent!\n")
            machine_status[mac_address] = "running"
        except:
            self.send_response(http.client.INTERNAL_SERVER_ERROR)
            self.end_headers()
            self.wfile.write(b"WoL packet sent!\n")

    def _stop(self, mac_address):
        ip = get_ip_from_mac(mac_address)
        if ip == None:
            self.send_response(http.client.INTERNAL_SERVER_ERROR)
            self.end_headers()
            self.wfile.write(b"No one available to shutdown the system!\n")
            return
        print("Shutting down {}...".format(ip))
        try:
            res = subprocess.check_output(["ssh", "ubuntu@{}".format(ip), "-i", "/home/naoki/.ssh/maas", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-t", "sudo poweroff"])
        except:
            None
        self.send_response(http.client.OK)
        self.end_headers()
        self.wfile.write(
            json.dumps(
                {"status": "running"}
            ).encode()
            + b"\n"
        )
        global machine_status
        machine_status[mac_address] = "stopped"

    def do_POST(self):
        if not self._authenticate():
            return
        # MAAS will send the the system_id in the header
        # system_id = self.headers.get("System_id")
        m = POST_REGEX.search(self.path)
        if m:
            if m.group("OP") == "start":
                self._start(m.group("MAC"))
            elif m.group("OP") == "stop":
                self._stop(m.group("MAC"))
        else:
            self._bad_path()


def main():
    parser = argparse.ArgumentParser(description="Web server to issue WoL commands")
    parser.add_argument(
        "--broadcast",
        "-b",
        default="255.255.255.255",
        type=str,
        help="The broadcast address to use for the wake on LAN command.",
    )
    parser.add_argument(
        "--broadcast-port",
        "-B",
        default=9,
        type=int,
        help="The broadcast port to use for the wake on LAN command.",
    )
    parser.add_argument(
        "--port",
        "-p",
        default=8080,
        type=int,
        help="The port to listen for requests on.",
    )
    parser.add_argument(
        "--username", "-u", type=str, help="The username required for remote use."
    )
    parser.add_argument(
        "--password", "-P", type=str, help="The password required for remote use."
    )
    parser.add_argument("--token", "-t", type=str, help="An authentication token.")
    args = parser.parse_args()

    global broadcast_ip, broadcast_port, username, password, token
    broadcast_ip = args.broadcast
    broadcast_port = args.broadcast_port
    username = args.username
    password = args.password
    token = args.token

    with socketserver.TCPServer(("", args.port), HTTPWoL) as httpd:

        def shutdown(*args, **kwargs):
            print("Shutting down...")
            httpd.server_close()
            sys.exit(0)

        print("Listening for requests...")
        signal.signal(signal.SIGINT, shutdown)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
