import os
import time
import shutil
import csv
import hashlib

# --- ค่าเริ่มต้นการทดลอง ---
NUM_TRIALS = 30
TEST_FILE_SOURCE = "./test_malware/small_downloader.exe" # ใช้ไฟล์ .exe เพื่อทดสอบแกนหลัก
HONEYPOT_PATH = "./honeypot_folder"
BLACKLIST_FILE = "./receiver_data/blacklist.json"
RESULTS_CSV = "./experiment_results.csv"

def calculate_hash(filepath):
    # ... (เหมือนกับใน honeypot_monitor.py) ...
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        return sha256.hexdigest()
    except IOError: return None

def check_blacklist(target_hash):
    """ตรวจสอบว่า hash อยู่ใน blacklist หรือไม่"""
    try:
        with open(BLACKLIST_FILE, 'r') as f:
            blacklist = json.load(f)
        return target_hash in blacklist
    except (FileNotFoundError, json.JSONDecodeError):
        return False
        
def main():
    print("Starting experiment to measure Time-to-Immunise...")
    # เตรียมไฟล์ CSV สำหรับเก็บผล
    with open(RESULTS_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['trial_number', 'time_to_immunise_seconds'])

    # คำนวณ Hash ของไฟล์ทดสอบไว้ล่วงหน้า
    target_hash = calculate_hash(TEST_FILE_SOURCE)
    if not target_hash:
        print("Error: Could not read test file.")
        return
        
    for i in range(1, NUM_TRIALS + 1):
        print(f"\n--- Running Trial {i}/{NUM_TRIALS} ---")
        
        # ล้างสถานะก่อนเริ่ม
        # ในการทดลองจริง อาจจะต้องมีวิธี reset blacklist, แต่เพื่อความง่าย เราจะใช้ไฟล์ใหม่ทุกรอบ
        trial_filename = f"malware_trial_{i}.exe"
        trial_filepath = os.path.join(HONEYPOT_PATH, trial_filename)
        trial_hash = calculate_hash(TEST_FILE_SOURCE) # สมมติว่า hash เหมือนเดิม

        # เริ่มจับเวลาและทิ้งไฟล์
        start_time = time.time()
        shutil.copy(TEST_FILE_SOURCE, trial_filepath)
        print(f"Dropped test file: {trial_filename}")
        
        # รอจนกว่า Blacklist จะอัปเดต
        while not check_blacklist(trial_hash):
            time.sleep(0.01) # เช็คทุกๆ 10ms
        
        end_time = time.time()
        
        # คำนวณและบันทึกผล
        time_taken = end_time - start_time
        print(f"Immunisation successful! Time taken: {time_taken:.4f} seconds.")
        
        with open(RESULTS_CSV, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([i, time_taken])
            
        # ลบไฟล์ทดลองเพื่อเตรียมรอบต่อไป
        os.remove(trial_filepath)
        # อาจจะต้องมีวิธีลบ hash ออกจาก blacklist เพื่อการทดลองที่บริสุทธิ์ในแต่ละรอบ
        # แต่นี่เป็นเวอร์ชันที่ง่ายที่สุด
        
    print("\nExperiment finished.")

if __name__ == "__main__":
    # ให้แน่ใจว่าได้รัน alert_receiver.py และ honeypot_monitor.py (แบบตรรกะระดับ 1) แล้ว
    main()