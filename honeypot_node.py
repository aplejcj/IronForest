import os
import sys
import time
import hashlib
import socket
import json
import threading
import random
import shutil
from datetime import datetime
import smtplib, ssl
from email.mime.text import MIMEText
import re
import pefile
import math
import yara
import requests

HONEYPOT_PATH = "./honeypot_folder"
QUARANTINE_PATH = "./quarantine"
BLACKLIST_FILE = "network_blacklist.json" 
CONFIG_FILE = "config.json"
WHITELIST_FILE = "whitelist.json"
YARA_RULES_PATH = "./malware_rules.yar"

pending_votes = {}
yara_rules = None
trusted_hashes = set()

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def load_yara_rules(path=YARA_RULES_PATH):
    global yara_rules
    try:
        yara_rules = yara.compile(filepath=path)
        print("[INFO] YARA rules loaded.")
    except Exception as e:
        print(f"[ERROR] Could not compile YARA rules: {e}")

def load_whitelist():
    global trusted_hashes
    try:
        with open(WHITELIST_FILE, 'r') as f:
            data = json.load(f)
        trusted_hashes = set(data.get('hashes', []))
        print(f"[INFO] Loaded {len(trusted_hashes)} trusted hashes.")
    except Exception:
        trusted_hashes = set()

def analyze_file(filepath):
    risk_score, reasons = 0, []
    try:
        with open(filepath, 'rb') as f: content = f.read()
        if yara_rules:
            matches = yara_rules.match(data=content)
            if matches:
                risk_score += 15
                reasons.append(f"YARA Match: {[m.rule for m in matches]}")
        
        content_len = len(content)
        if content_len > 0:
            entropy = math.fsum(- (p_x/content_len) * math.log(p_x/content_len, 2) for p_x in [content.count(byte) for byte in range(256)] if p_x > 0)
            if entropy > 7.5:
                risk_score += 10
                reasons.append(f"High Entropy ({entropy:.2f})")
    except Exception: pass
    return risk_score, reasons

def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""): sha256.update(byte_block)
        return sha256.hexdigest()
    except IOError: return None

def quarantine_file(filepath, filename, node_addr):
    if not os.path.exists(QUARANTINE_PATH): os.makedirs(QUARANTINE_PATH)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    quarantined_filename = f"{timestamp}_{node_addr.replace(':', '_')}_{filename}"
    destination_path = os.path.join(QUARANTINE_PATH, quarantined_filename)
    try:
        shutil.move(filepath, destination_path)
        return True
    except Exception as e:
        print(f"[{node_addr}] FAILED to quarantine file '{filename}': {e}")
        return False

def log_to_observer(log_msg, config):
    try:
        host, port_str = config['observer_addr'].split(':')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, int(port_str)))
            s.sendall(log_msg.encode('utf-8'))
    except Exception: pass

def gossip_threat(threat_data, peers, gossip_count, node_addr, config):
    selected_peers = random.sample(peers, min(len(peers), gossip_count))
    log_to_observer(f"[{node_addr}] Gossiping threat to {selected_peers}", config)
    for peer in selected_peers:
        try:
            host, port_str = peer.split(':')
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, int(port_str)))
                s.sendall(json.dumps(threat_data).encode('utf-8'))
        except Exception: pass

def update_network_blacklist(file_hash, node_addr, config):
    try:
        with open(BLACKLIST_FILE, 'r') as f: blacklist = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): blacklist = {}
    if file_hash not in blacklist:
        blacklist[file_hash] = datetime.now().isoformat()
        with open(BLACKLIST_FILE, 'w') as f: json.dump(blacklist, f, indent=4)
        log_msg = f"[{node_addr}] NETWORK BLACKLISTED: Hash {file_hash[:10]}... reached quorum."
        print(log_msg)
        log_to_observer(log_msg, config)

def threat_listener(node_port, node_addr, config):
    host = "127.0.0.1"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, node_port))
        s.listen()
        log_to_observer(f"[{node_addr}] Listener started.", config)
        while True:
            conn, _ = s.accept()
            with conn:
                data = conn.recv(1024)
                if data:
                    threat = json.loads(data.decode('utf-8'))
                    file_hash, source_node = threat.get('hash'), threat.get('source_node')
                    log_msg = f"[{node_addr}] <- Received vote for hash {file_hash[:10]} from {source_node}"
                    print(log_msg)
                    log_to_observer(log_msg, config)
                    
                    pending_votes.setdefault(file_hash, set()).add(source_node)
                    if len(pending_votes[file_hash]) >= config['vote_threshold']:
                        update_network_blacklist(file_hash, node_addr, config)

def yara_updater(config):
    while True:
        try:
            print("[YARA] Checking for rule updates...")
            response = requests.get(config['yara_rules_url'], timeout=10)
            if response.status_code == 200:
                with open(YARA_RULES_PATH, 'wb') as f: f.write(response.content)
                load_yara_rules()
        except Exception as e: print(f"[YARA] Update failed: {e}")
        time.sleep(config['yara_update_interval_sec'])

def main():
    if len(sys.argv) < 2:
        print("Usage: python honeypot_node.py <port_for_this_node>")
        return
    
    config = load_config()
    load_yara_rules()
    load_whitelist()
    
    node_port = int(sys.argv[1])
    node_addr = f"127.0.0.1:{node_port}"
    peers = [p for p in config['peer_nodes'] if p != node_addr]

    threading.Thread(target=threat_listener, args=(node_port, node_addr, config), daemon=True).start()
    threading.Thread(target=yara_updater, args=(config,), daemon=True).start()

    log_to_observer(f"[{node_addr}] Node started.", config)
    known_files = set(os.listdir(HONEYPOT_PATH))
    
    while True:
        try:
            new_files = set(os.listdir(HONEYPOT_PATH)) - known_files
            if new_files:
                for filename in new_files:
                    filepath = os.path.join(HONEYPOT_PATH, filename)
                    file_hash = get_file_hash(filepath)

                    if not file_hash or file_hash in trusted_hashes:
                        known_files.add(filename)
                        continue
                    
                    risk_score, reasons = analyze_file(filepath)
                    if risk_score >= config['risk_threshold']:
                        log_msg = f"[{node_addr}] DETECTED: {filename} (Score: {risk_score})"
                        print(log_msg)
                        log_to_observer(log_msg, config)
                        
                        if quarantine_file(filepath, filename, node_addr):
                            threat_data = {"hash": file_hash, "source_node": node_addr}
                            pending_votes.setdefault(file_hash, set()).add(node_addr)
                            gossip_threat(threat_data, peers, config['gossip_count'], node_addr, config)
                            if len(pending_votes[file_hash]) >= config['vote_threshold']:
                                update_network_blacklist(file_hash, node_addr, config)
                        continue
                
                known_files = new_files.union(known_files)
            time.sleep(2)
        except KeyboardInterrupt:
            log_to_observer(f"[{node_addr}] Node stopped.", config)
            break

if __name__ == "__main__":
    main()