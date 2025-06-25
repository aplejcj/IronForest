import socket
import json
from datetime import datetime, timedelta

HOST = '127.0.0.1'
PORT = 9999
BLACKLIST_FILE = './receiver_data/blacklist.json'
REPUTATION_FILE = './receiver_data/reputation_log.json'
POLICY_FILE = './receiver_data/proactive_policy.json'

def read_json_file(filepath):
    try:
        with open(filepath, 'r') as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): return {}

def write_json_file(filepath, data):
    with open(filepath, 'w') as f: json.dump(data, f, indent=4)

def process_alert(data):
    source_node = data.get('source_node', 'Unknown_Node')
    file_hash = data.get('hash')
    filename = data.get('filename')
    file_type = data.get('file_type')
    extension = data.get('extension')

    print(f"\n[ALERT RECEIVED] From: {source_node} for file: {filename}")
    
    # 1. Update Blacklist
    blacklist = read_json_file(BLACKLIST_FILE)
    if file_hash not in blacklist:
        blacklist[file_hash] = datetime.now().isoformat()
        write_json_file(BLACKLIST_FILE, blacklist)
        print(f"[BLACKLIST UPDATED] Added hash: {file_hash[:10]}...")

    # 2. Proactive Defense
    if file_type == 'script':
        policy = read_json_file(POLICY_FILE)
        expiry_time = (datetime.now() + timedelta(minutes=5)).isoformat()
        if 'blocked_extensions' not in policy: policy['blocked_extensions'] = {}
        policy['blocked_extensions'][extension] = expiry_time
        write_json_file(POLICY_FILE, policy)
        print(f"[PROACTIVE DEFENSE] Blocking '{extension}' files until {expiry_time}")
        
    # 3. Update Reputation
    reputation = read_json_file(REPUTATION_FILE)
    if source_node not in reputation: reputation[source_node] = 10
    reputation[source_node] += 1
    write_json_file(REPUTATION_FILE, reputation)
    print(f"[REPUTATION UPDATE] Reputation for {source_node} increased to {reputation[source_node]}")

def main():
    print("Alert Receiver started. Waiting for connections...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    data = conn.recv(1024)
                    if data:
                        alert_data = json.loads(data.decode('utf-8'))
                        process_alert(alert_data)
            except KeyboardInterrupt:
                print("\nAlert Receiver stopped.")
                break
if __name__ == "__main__":
    main()