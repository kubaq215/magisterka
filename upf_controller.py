#!/usr/bin/env python3
"""
upf_controller.py
Role: Control Plane
1. Receives complex JSON Session info from Open5GS (C-Code) via REST.
2. Configures OVS to steer traffic into the TUN interface.
3. Sends simplified "ADD/DEL" commands to the Dataplane script via UDP.
"""

import logging
import socket
import subprocess
from flask import Flask, request, jsonify

# Configuration
DATAPLANE_IP = "127.0.0.1"
DATAPLANE_PORT = 5555
TUN_INTERFACE = "gtp0"  # The interface OVS sends traffic to

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [CTRL] - %(message)s')
app = Flask(__name__)

# State Store: { session_id: { "ue_ip": "...", "teid_out": 123, "remote_ip": "..." } }
session_store = {}

# --- Helpers ---

def send_to_dataplane(message):
    """Sends a text command to the running dataplane script."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(message.encode(), (DATAPLANE_IP, DATAPLANE_PORT))
        logging.info(f"Sent to Dataplane: {message}")
    except Exception as e:
        logging.error(f"Failed to contact Dataplane: {e}")
    finally:
        sock.close()

def ovs_add_steering(ue_ip):
    """OVS: 'If Dest IP is UE_IP, send to gtp0 interface'"""
    if ue_ip == "N/A": return
    # Adjust 'br0' to your actual bridge name
    cmd = f"ovs-ofctl add-flow br0 priority=100,ip,nw_dst={ue_ip},actions=output:{TUN_INTERFACE}"
    logging.info(f"[OVS] Steering added for {ue_ip}")
    # subprocess.run(cmd, shell=True) 

def ovs_del_steering(ue_ip):
    if ue_ip == "N/A": return
    cmd = f"ovs-ofctl del-flows br0 ip,nw_dst={ue_ip}"
    logging.info(f"[OVS] Steering removed for {ue_ip}")
    # subprocess.run(cmd, shell=True)

# --- Logic ---

def reconcile_session(session_id, new_state):
    global session_store
    old_state = session_store.get(session_id)

    # 1. NEW SESSION
    if not old_state:
        logging.info(f"New Session: {session_id}")
        if new_state['ue_ip'] != "N/A":
            # A. Configure OVS
            ovs_add_steering(new_state['ue_ip'])
            # B. Configure Dataplane (TEID Mapping)
            msg = f"ADD {new_state['ue_ip']} {new_state['teid_out']} {new_state['remote_ip']}"
            send_to_dataplane(msg)
        
        session_store[session_id] = new_state
        return

    # 2. MODIFICATION
    logging.info(f"Modifying Session: {session_id}")
    
    # Check if UE IP changed (requires delete + add)
    if old_state['ue_ip'] != new_state['ue_ip']:
        # Cleanup Old
        ovs_del_steering(old_state['ue_ip'])
        send_to_dataplane(f"DEL {old_state['ue_ip']}")
        
        # Add New
        if new_state['ue_ip'] != "N/A":
            ovs_add_steering(new_state['ue_ip'])
            msg = f"ADD {new_state['ue_ip']} {new_state['teid_out']} {new_state['remote_ip']}"
            send_to_dataplane(msg)

    # Check if TEID/Remote changed (Just update dataplane)
    elif (old_state['teid_out'] != new_state['teid_out'] or 
          old_state['remote_ip'] != new_state['remote_ip']):
        
        if new_state['ue_ip'] != "N/A":
            msg = f"ADD {new_state['ue_ip']} {new_state['teid_out']} {new_state['remote_ip']}"
            send_to_dataplane(msg)

    session_store[session_id] = new_state

# --- REST Endpoint ---

@app.route('/api/session', methods=['POST'])
def handle_session_update():
    try:
        data = request.json
        sess_id = data.get('session_id')
        pdrs = data.get('pdrs', [])
        fars = data.get('fars', [])
        
        # Logic to extract the active Access-Side TEID
        teid_out = 0
        remote_ip = "0.0.0.0"

        # Find the FAR sending to Access (Downlink)
        for far in fars:
            if far.get('dst_if') == "Access": 
                teid_out = far.get('teid_out', 0)
                remote_ip = far.get('remote_ip', "0.0.0.0")

        new_state = {
            "ue_ip": data.get('ue_ip', "N/A"),
            "teid_out": teid_out,
            "remote_ip": remote_ip
        }

        reconcile_session(sess_id, new_state)
        return jsonify({"status": "ok"})

    except Exception as e:
        logging.error(f"API Error: {e}")
        return jsonify({"status": "error"}), 500

if __name__ == '__main__':
    # Listen on port 8080 for Open5GS
    app.run(host='0.0.0.0', port=8080)