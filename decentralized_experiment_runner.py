import os
import time
import shutil
import csv
import hashlib
import json

NUM_TRIALS = 30
TEST_FILE_SOURCE = "./test_malware/script.ps1"
HONEYPOT_PATH = "./honeypot_folder"
STATE_PATH = "./state"
NETWORK_BLACKLIST_FILE = os.path.join(STATE_PATH, "network_blacklist.json")
PENDING_VOTES_FILE = os.path.join(STATE_PATH, "pending_votes.json")
RESULTS_CSV = "./decentralized_results.csv"

def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        return sha256.hexdigest()
    except IOError:
        return None

def check_network_blacklist(target_hash):
    try:
        if not os.path.exists(NETWORK_BLACKLIST_FILE):
            return False
        with open(NETWORK_BLACKLIST_FILE, 'r') as f:
            blacklist = json.load(f)
        return target_hash in blacklist
    except (FileNotFoundError, json.JSONDecodeError):
        return False

def clear_workspace():
    if os.path.exists(HONEYPOT_PATH):
        for filename in os.listdir(HONEYPOT_PATH):
            file_path = os.path.join(HONEYPOT_PATH, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
    if os.path.exists(NETWORK_BLACKLIST_FILE):
        os.remove(NETWORK_BLACKLIST_FILE)
    if os.path.exists(PENDING_VOTES_FILE):
        os.remove(PENDING_VOTES_FILE)

def main():
    print("--- Decentralized Experiment Runner ---")
    print("Measures the 'Time-to-Quorum' for the IronForest network.")
    print("\n!!! IMPORTANT: Make sure all honeypot_node.py instances are running in other terminals. !!!")
    time.sleep(5)
    if not os.path.exists(STATE_PATH):
        os.makedirs(STATE_PATH)
    with open(RESULTS_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['trial_number', 'time_to_quorum_seconds'])
    target_hash = get_file_hash(TEST_FILE_SOURCE)
    if not target_hash:
        print(f"Error: Could not read hash from test file '{TEST_FILE_SOURCE}'")
        return
    for i in range(1, NUM_TRIALS + 1):
        clear_workspace()
        print(f"\n--- Running Trial {i}/{NUM_TRIALS} ---")
        time.sleep(1)
        trial_filename = f"threat_trial_{int(time.time())}_{i}.ps1"
        trial_filepath = os.path.join(HONEYPOT_PATH, trial_filename)
        start_time = time.time()
        shutil.copy(TEST_FILE_SOURCE, trial_filepath)
        timeout_seconds = 20
        wait_start_time = time.time()
        quorum_reached = False
        while time.time() - wait_start_time < timeout_seconds:
            if check_network_blacklist(target_hash):
                quorum_reached = True
                break
            time.sleep(0.01)
        if quorum_reached:
            end_time = time.time()
            time_taken = end_time - start_time
            print(f"Quorum reached! Time taken: {time_taken:.4f} seconds.")
            with open(RESULTS_CSV, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([i, time_taken])
        else:
            print(f"Timeout! Network blacklist was not updated within {timeout_seconds} seconds.")
            with open(RESULTS_CSV, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([i, "timeout"])
    print("\nExperiment finished.")

if __name__ == "__main__":
    main()