import socket
import json
from datetime import datetime, timedelta
import smtplib
import ssl
from email.mime.text import MIMEText

# --- ค่าเริ่มต้นของระบบ ---
HOST = '127.0.0.1'
PORT = 9999
BLACKLIST_FILE = './receiver_data/blacklist.json'
REPUTATION_FILE = './receiver_data/reputation_log.json'
POLICY_FILE = './receiver_data/proactive_policy.json'

# --- การตั้งค่าสำหรับส่งอีเมล (กรุณากรอกข้อมูลของคุณเอง) ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "plankton.nawa@gmail.com" # ใส่อีเมลของคุณที่จะใช้ส่ง
SENDER_PASSWORD = "mbes jdnw xzwh gtnk" # ใส่ App Password 16 หลัก

# ใส่อีเมลของทุกคนในองค์กรที่คุณต้องการให้รับการแจ้งเตือน
RECEIVER_EMAILS = [
    "putana8585@gmail.com", # ใส่อีเมลของผู้รับคนแรก
    # ... เพิ่มอีเมลอื่นๆ ตามต้องการ ...
]

def send_email_notification(filename, extension, block_duration_minutes):
    context = ssl.create_default_context()

    subject = f"[IronForest: {filename}"
    body = f"""
    เรียน ทีมงาน,

    ระบบ IronForest ได้ตรวจพบและจัดการไฟล์ต้องสงสัยโดยอัตโนมัติ

    รายละเอียด:
    - ชื่อไฟล์: {filename}
    - ประเภทไฟล์ (นามสกุล): {extension}

    การดำเนินการ:
    1. [BLACKLISTED] ไฟล์นี้ถูกเพิ่มเข้าไปใน Blacklist อย่างถาวรแล้ว
    2. [PROACTIVE BLOCK] นโยบายป้องกันเชิงรุกได้ถูกเปิดใช้งาน ทำให้ไฟล์นามสกุล '{extension}' ทั้งหมดจะถูกบล็อกการทำงานชั่วคราวเป็นเวลา {block_duration_minutes} นาที

    ขอแสดงความนับถือ,
    ระบบ IronForest
    """
    
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = ", ".join(RECEIVER_EMAILS)

    try:
        print(f"[EMAIL] กำลังส่งอีเมลแจ้งเตือนไปยังผู้รับ {len(RECEIVER_EMAILS)} คน...")
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
        print(f"[EMAIL] ส่งการแจ้งเตือนสำหรับไฟล์ '{filename}' สำเร็จ!")
    except Exception as e:
        print(f"[EMAIL ERROR] ไม่สามารถส่งอีเมลได้: {e}")

def read_json_file(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def write_json_file(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

def process_alert(data):
    source_node = data.get('source_node', 'Unknown_Node')
    file_hash = data.get('hash')
    filename = data.get('filename')
    file_type = data.get('file_type')
    extension = data.get('extension')

    print(f"\n[ALERT RECEIVED] From: {source_node} for file: {filename}")
    
    blacklist = read_json_file(BLACKLIST_FILE)
    if file_hash not in blacklist:
        blacklist[file_hash] = datetime.now().isoformat()
        write_json_file(BLACKLIST_FILE, blacklist)
        print(f"[BLACKLIST UPDATED] Added hash: {file_hash[:10]}...")

    block_duration = 5
    if file_type == 'script':
        policy = read_json_file(POLICY_FILE)
        expiry_time = (datetime.now() + timedelta(minutes=block_duration)).isoformat()
        if 'blocked_extensions' not in policy:
            policy['blocked_extensions'] = {}
        policy['blocked_extensions'][extension] = expiry_time
        write_json_file(POLICY_FILE, policy)
        print(f"[PROACTIVE DEFENSE] Blocking '{extension}' files for {block_duration} minutes.")
        
    reputation = read_json_file(REPUTATION_FILE)
    if source_node not in reputation:
        reputation[source_node] = 10
    reputation[source_node] += 1
    write_json_file(REPUTATION_FILE, reputation)
    print(f"[REPUTATION UPDATE] Reputation for {source_node} increased to {reputation[source_node]}")

    send_email_notification(filename, extension, block_duration)

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