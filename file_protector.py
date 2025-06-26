import sys
import os
import json
import hashlib
from datetime import datetime

BLACKLIST_FILE = './receiver_data/blacklist.json'
POLICY_FILE = './receiver_data/proactive_policy.json'

def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        return sha256.hexdigest()
    except IOError: return None

def read_json_file(filepath):
    try:
        with open(filepath, 'r') as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): return {}
    
def main():
    if len(sys.argv) < 2:
        print("Usage: python file_protector.py <filepath>")
        return

    filepath = sys.argv[1]
    filename = os.path.basename(filepath)
    extension = os.path.splitext(filename)[1].lower()
    
    # 1. Check Proactive Policy
    policy = read_json_file(POLICY_FILE)
    if 'blocked_extensions' in policy and extension in policy['blocked_extensions']:
        expiry_time = datetime.fromisoformat(policy['blocked_extensions'][extension])
        if datetime.now() < expiry_time:
            print(f"[ACCESS DENIED] Execution of '{extension}' files is temporarily blocked by a proactive policy.")
            return

    # 2. Check Blacklist
    file_hash = calculate_hash(filepath)
    blacklist = read_json_file(BLACKLIST_FILE)
    if file_hash and file_hash in blacklist:
        print(f"[ACCESS DENIED] File '{filename}' is on the blacklist.")
        return
        
    print(f"[SAFE] File '{filename}' appears to be safe.")

if __name__ == "__main__":
    main()