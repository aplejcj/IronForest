import os
import time
import hashlib
import socket
import json

# --- ค่าเริ่มต้นของระบบ ---
HONEYPOT_PATH = "./honeypot_folder"
RECEIVER_IP = "127.0.0.1"
RECEIVER_PORT = 9999
NODE_NAME = "Node_A"

def calculate_hash(filepath):
    """คำนวณค่า SHA-256 ของไฟล์"""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        return sha256.hexdigest()
    except IOError:
        print(f"Error: Cannot read file {filepath}")
        return None

def analyze_file(filepath):
    """วิเคราะห์ไฟล์และสร้าง Alert Payload (Heuristic)"""
    file_hash = calculate_hash(filepath)
    if not file_hash:
        return None

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    extension = os.path.splitext(filename)[1].lower()
    
    risk_score = 0
    reasons = []

    if extension in ['.exe', '.dll', '.ps1', '.bat', '.vbs']:
        risk_score += 5
        reasons.append(f"Dangerous extension ({extension})")

    if extension == '.exe' and filesize < 1024:
        risk_score += 3
        reasons.append("Suspiciously small executable size")
        
    file_type = "script" if extension in ['.ps1', '.bat', '.vbs'] else "executable" if extension == '.exe' else "unknown"

    alert_data = {
        "hash": file_hash, "filename": filename, "file_type": file_type, "extension": extension,
        "risk_score": risk_score, "reasons": reasons, "source_node": NODE_NAME
    }
    return alert_data

def send_alert(alert_data):
    """ส่งข้อมูล Alert ไปยัง Receiver"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((RECEIVER_IP, RECEIVER_PORT))
            message = json.dumps(alert_data).encode('utf-8')
            s.sendall(message)
            print(f"[SENT ALERT] Sent alert for {alert_data['filename']} to {RECEIVER_IP}")
    except Exception as e:
        print(f"Error sending alert: {e}")

def main():
    print(f"Honeypot Monitor started on '{HONEYPOT_PATH}'...")
    known_files = set(os.listdir(HONEYPOT_PATH))
    
    while True:
        try:
            current_files = set(os.listdir(HONEYPOT_PATH))
            new_files = current_files - known_files

            if new_files:
                for filename in new_files:
                    filepath = os.path.join(HONEYPOT_PATH, filename)
                    print(f"\n[DETECTED] New file: {filename}")
                    
                    # ใช้ Heuristic Analysis สำหรับการจำลองสถานการณ์
                    alert_payload = analyze_file(filepath)
                    if alert_payload and alert_payload['risk_score'] >= 5:
                        print(f"[ANALYSIS] Risk Score: {alert_payload['risk_score']}. Reasons: {alert_payload['reasons']}")
                        send_alert(alert_payload)
                    else:
                        print("[INFO] File does not meet risk threshold.")
                known_files = current_files
            time.sleep(2)
        except KeyboardInterrupt:
            print("\nHoneypot Monitor stopped.")
            break
if __name__ == "__main__":
    main()
def main():
    print(f"Honeypot Monitor (Experiment Mode) started on '{HONEYPOT_PATH}'...")
    known_files = set(os.listdir(HONEYPOT_PATH))
    
    while True:
        try:
            current_files = set(os.listdir(HONEYPOT_PATH))
            new_files = current_files - known_files

            if new_files:
                for filename in new_files:
                    filepath = os.path.join(HONEYPOT_PATH, filename)
                    print(f"\n[DETECTED - Experiment Mode] New file: {filename}")
                    
                    # ==========================================================
                    #  ส่วนที่ปรับแก้: ใช้ตรรกะระดับ 1 (Honeypot Trigger)
                    #  ส่ง Alert ทันทีที่เจอไฟล์เพื่อวัดเวลาตอบสนองที่บริสุทธิ์
                    # ==========================================================
                    alert_payload = {
                        "hash": calculate_hash(filepath),
                        "filename": filename,
                        "file_type": "experiment_trigger", # ระบุว่าเป็นโหมดทดลอง
                        "extension": os.path.splitext(filename)[1].lower(),
                        "source_node": NODE_NAME
                    }
                    send_alert(alert_payload)
                    # ==========================================================

                known_files = current_files
            
            time.sleep(0.1) # ลดเวลาหน่วงลงเล็กน้อยเพื่อการตอบสนองที่เร็วขึ้นในการทดลอง

        except KeyboardInterrupt:
            print("\nHoneypot Monitor stopped.")
            break