import os
import time
import hashlib
import socket
import json
import re
import pefile   
import math     
import yara     

# --- ค่าเริ่มต้นของระบบ ---
HONEYPOT_PATH = "./honeypot_folder"
RECEIVER_IP = "127.0.0.1"
RECEIVER_PORT = 9999
NODE_NAME = "Node_A"
RISK_THRESHOLD = 20 
YARA_RULES_PATH = "./malware_rules.yar"

try:
    yara_rules = yara.compile(filepath=YARA_RULES_PATH)
    print("[INFO] YARA rules compiled successfully.")
except yara.Error as e:
    print(f"[ERROR] Could not compile YARA rules: {e}")
    yara_rules = None

def calculate_entropy(data):
    """คำนวณค่า Entropy ของข้อมูล"""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x.to_bytes(1, 'little'))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_file_ultimate(filepath):
    """
    วิเคราะห์ไฟล์ด้วยเทคนิคจัดเต็ม และคืนค่าเป็นคะแนนความเสี่ยง (Risk Score)
    """
    risk_score = 0
    reasons = []
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read()

        # 1. YARA Rule Scan 
        if yara_rules:
            matches = yara_rules.match(data=content)
            if matches:
                risk_score += 15 # คะแนนเริ่มต้นสูงมาก
                matched_rules = [match.rule for match in matches]
                reasons.append(f"YARA match: {', '.join(matched_rules)}")

        # 2. Entropy Analysis
        entropy = calculate_entropy(content)
        if entropy > 7.5: # ค่า Entropy สูงมาก (ปกติไฟล์โปรแกรมจะอยู่ที่ 4.8-6.5)
            risk_score += 10
            reasons.append(f"High entropy ({entropy:.2f}), possibly packed/encrypted")

        # 3. Advanced PE Analysis (ถ้าเป็นไฟล์ PE)
        if content.startswith(b'MZ'): # ตรวจสอบเบื้องต้นว่าเป็นไฟล์ PE
            pe = pefile.PE(data=content, fast_load=True)
            
            # 3.1 Entry Point Analysis
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            in_code_section = False
            for section in pe.sections:
                if section.contains_rva(entry_point):
                    if b'.text' in section.Name or b'CODE' in section.Name:
                        in_code_section = True
                    break
            if not in_code_section:
                risk_score += 7
                reasons.append("Entry point is outside the main code section")
            
            # 3.2 Suspicious Section Names
            for section in pe.sections:
                if section.Name.startswith(b'.UPX') or section.Name.startswith(b'.aspack'):
                    risk_score += 5
                    reasons.append(f"Found suspicious section name: {section.Name.decode(errors='ignore')}")

            # 3.3 Suspicious Imports (เสริมจากเดิม)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if entry.dll.lower() == b'kernel32.dll':
                        for imp in entry.imports:
                            if imp.name and imp.name.lower() in [b'loadlibrary', b'getprocaddress']:
                                risk_score += 3
                                reasons.append("Imports LoadLibrary/GetProcAddress (common in malware)")

    except Exception as e:
        # print(f"  [!] Could not fully analyze {os.path.basename(filepath)}: {e}")
        pass

    return risk_score, reasons

def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        return sha256.hexdigest()
    except IOError: return None

def send_alert(alert_data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((RECEIVER_IP, RECEIVER_PORT))
            s.sendall(json.dumps(alert_data).encode('utf-8'))
            print(f"[SENT ALERT] Sent alert for {alert_data['filename']}")
    except Exception as e:
        print(f"Error sending alert: {e}")

def main():
    print("Honeypot Monitor (Ultimate Engine) started...")
    print(f"Alerting on files with risk score >= {RISK_THRESHOLD}")
    known_files = set(os.listdir(HONEYPOT_PATH))
    
    while True:
        try:
            current_files = set(os.listdir(HONEYPOT_PATH))
            new_files = current_files - known_files
            if new_files:
                for filename in new_files:
                    filepath = os.path.join(HONEYPOT_PATH, filename)
                    print(f"\n[DETECTED] New file: {filename}")
                    
                    risk_score, reasons = analyze_file_ultimate(filepath)
                    print(f"[ULTIMATE ANALYSIS] Risk Score: {risk_score}. Reasons: {reasons if reasons else 'N/A'}")
                    
                    if risk_score >= RISK_THRESHOLD:
                        print(f"[ACTION] Risk score exceeds threshold. Generating alert.")
                        file_hash = calculate_hash(filepath)
                        if file_hash:
                            send_alert({
                                "hash": file_hash, "filename": filename,
                                "file_type": "executable", "extension": os.path.splitext(filename)[1].lower(),
                                "risk_score": risk_score, "reasons": reasons, "source_node": NODE_NAME
                            })
                    else:
                        print("[ACTION] File does not meet risk threshold. Ignoring.")
                
                known_files = current_files
            time.sleep(2)
        except KeyboardInterrupt:
            print("\nHoneypot Monitor stopped.")
            break

if __name__ == "__main__":
    main()