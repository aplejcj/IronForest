import os
import time
import shutil
import csv
import hashlib
import json  

# --- ค่าเริ่มต้นการทดลอง ---
NUM_TRIALS = 30
TEST_FILE_SOURCE = "./test_malware/small_downloader.exe"
HONEYPOT_PATH = "./honeypot_folder"
BLACKLIST_FILE = "./receiver_data/blacklist.json"
RESULTS_CSV = "./experiment_results.csv"

def calculate_hash(filepath):
    """คำนวณค่า SHA-256 ของไฟล์"""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        return sha256.hexdigest()
    except IOError:
        return None

def check_blacklist(target_hash):
    """ตรวจสอบว่า hash อยู่ใน blacklist หรือไม่"""
    try:
        with open(BLACKLIST_FILE, 'r') as f:
            blacklist = json.load(f)
        return target_hash in blacklist
    except (FileNotFoundError, json.JSONDecodeError):
        # ถ้าหาไฟล์ไม่เจอ หรือไฟล์ยังว่างอยู่ ก็ถือว่ายังไม่มี hash
        return False
        
def main():
    print("Starting experiment to measure Time-to-Immunise...")
    
    # ตรวจสอบว่าไฟล์และโฟลเดอร์ที่จำเป็นมีอยู่หรือไม่
    if not os.path.exists(TEST_FILE_SOURCE):
        print(f"Error: Test file not found at '{TEST_FILE_SOURCE}'")
        return
    if not os.path.exists(HONEYPOT_PATH):
        print(f"Error: Honeypot path not found at '{HONEYPOT_PATH}'")
        return
        
    # เตรียมไฟล์ CSV สำหรับเก็บผล
    with open(RESULTS_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['trial_number', 'time_to_immunise_seconds'])

    # คำนวณ Hash ของไฟล์ทดสอบไว้ล่วงหน้า
    target_hash = calculate_hash(TEST_FILE_SOURCE)
    if not target_hash:
        print(f"Error: Could not read hash from test file '{TEST_FILE_SOURCE}'")
        return
        
    print("Please ensure alert_receiver.py and honeypot_monitor.py (experiment version) are running...")
    time.sleep(3) # รอ 3 วินาทีเพื่อให้แน่ใจว่าระบบพร้อม

    for i in range(1, NUM_TRIALS + 1):
        print(f"\n--- Running Trial {i}/{NUM_TRIALS} ---")
        
        # สร้างชื่อไฟล์ที่ไม่ซ้ำกันในแต่ละรอบ
        trial_filename = f"malware_trial_{int(time.time())}_{i}.exe"
        trial_filepath = os.path.join(HONEYPOT_PATH, trial_filename)
        
        # เริ่มจับเวลาและทิ้งไฟล์
        start_time = time.time()
        shutil.copy(TEST_FILE_SOURCE, trial_filepath)
        # print(f"Dropped test file: {trial_filename}")
        
        # รอจนกว่า Blacklist จะอัปเดต หรือหมดเวลา (Timeout)
        timeout_seconds = 10 # ป้องกันการค้าง
        wait_start_time = time.time()
        immunised = False
        while time.time() - wait_start_time < timeout_seconds:
            # เราต้องใช้ hash ของไฟล์ต้นฉบับในการเช็ค ไม่ใช่ hash ของไฟล์ที่สร้างใหม่
            if check_blacklist(target_hash):
                immunised = True
                break
            time.sleep(0.01)
        
        if immunised:
            end_time = time.time()
            time_taken = end_time - start_time
            print(f"Immunisation successful! Time taken: {time_taken:.4f} seconds.")
            with open(RESULTS_CSV, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([i, time_taken])
        else:
            print(f"Timeout! Blacklist was not updated within {timeout_seconds} seconds.")
            with open(RESULTS_CSV, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([i, "timeout"])

        # ลบไฟล์ทดลองเพื่อเตรียมรอบต่อไป
        if os.path.exists(trial_filepath):
            os.remove(trial_filepath)
        
    print("\nExperiment finished.")

if __name__ == "__main__":
    main()