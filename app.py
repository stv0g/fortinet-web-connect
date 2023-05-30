# SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
# SPDX-License-Identifier: Apache-2.0

import humanize
import os
import json
import logging
import psutil
import signal
import subprocess
from datetime import datetime

from flask import Flask, render_template, request, redirect

INTERFACE_NAME = "tun0"
INTERFACE_GROUP = "vpn"

PID_FILE = "/var/run/openconnect.pid"

SERVER_ADDR = "https://remote.opal-rt.com:10443"
SERVER_CERT = "pin-sha256:w85ax3vbWHDSE7n7YFoUiaHm4UcGehOULVsgtgHu+ks="

current_pid = None
current_user = None

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD "] = True

@app.route("/")
def home():
    status = get_status()

    return render_template("index.html.j2", **status)

@app.route("/connect", methods=["POST"])
def connect():

    username = request.form.get("username")
    password = request.form.get("password")
    token = request.form.get("token")

    openconnect_connect(username, password, token)
    
    return redirect("/", code=302)

@app.route("/disconnect", methods=["POST"])
def disconnect():
    openconnect_disconnect()

    return redirect("/", code=302)

@app.template_filter("naturalsize")
def naturalsize(s):
    return humanize.naturalsize(s)

@app.template_filter("naturaldelta")
def naturaldelta(s):
    return humanize.naturaldelta(s)

def get_current_pid() -> int:
    try:
        with open(PID_FILE, "r") as f:
            return int(f.read())
    except:
        return None

def get_status_interface():
    cp = subprocess.run(["ip",
        "-json",
        "-details",
        "-stats", "-stats",
        "address", "show", "dev", INTERFACE_NAME],
        capture_output=True)

    if cp.returncode == 0:
        interface = json.loads(cp.stdout)
        
        if len(interface) == 1:
            return interface[0]

def get_status_routes():
    cp = subprocess.run(["ip",
        "-json",
        "-details",
        "route", "list"],
        capture_output=True)

    if cp.returncode == 0:
        routes = json.loads(cp.stdout)
        
        return [r for r in routes if r["dev"] == INTERFACE_NAME]

def get_status():    
    status = {
        "connected": current_pid is not None,
        "current_user": current_user,
    }

    if interface := get_status_interface():
        status.update({
            "interface": interface
        })

    if routes := get_status_routes():
        status.update({
            "routes": routes
        })

    if current_pid is not None:
        proc = psutil.Process(current_pid)

        create_ts = datetime.fromtimestamp(proc.create_time())

        status.update({
            "pid": current_pid,
            "connected_timestamp": create_ts,
            "connected_time": datetime.now() - create_ts,
        })

    return status    

def openconnect_connect(username: str, password: str, token: str):
    global current_user
    global current_pid

    process = subprocess.Popen([
        "openconnect",
            "--background",
            "--pid-file", PID_FILE,
            "--passwd-on-stdin",
            "--protocol", "fortinet",
            "--user", username,
            "--interface", INTERFACE_NAME,
            "--servercert", SERVER_CERT,
           SERVER_ADDR
        ],
        stdin=subprocess.PIPE,
        encoding="ascii")

    stdout, stderr = process.communicate(password + "\n" + token)

    if process.returncode != 0:
        raise Exception("Failed to start openconnect")

    logging.info("Placing device %s in interface group %s", INTERFACE_NAME, INTERFACE_GROUP)
    subprocess.run(["ip", "link", "set", INTERFACE_NAME, "group", INTERFACE_GROUP])

    logging.info("Configuring IP forwarding")
    subprocess.run(["sysctl", "net.ipv4.ip_forward=1"])

    with open(PID_FILE, "r") as f:
        current_pid = int(f.read())
        
    current_user = username

def openconnect_disconnect():
    global current_pid
    global current_user

    if current_pid is None:
        return

    os.kill(current_pid, signal.SIGTERM)

    current_pid = None
    current_user = None

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    current_pid = get_current_pid()
    if current_pid:
        logging.info("OpenConnect is already running with PID: %d", current_pid)
    else:
        logging.info("OpenConnect is not already running yet")

    app.run(
        host="::",
        port=443,
        ssl_context=('cert.pem', 'key.pem'))
