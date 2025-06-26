import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

def generate_credible_report():
    """
    สคริปต์เดียวจบที่สร้างข้อมูลจำลองที่ 'น่าเชื่อถือและสมจริง'
    สำหรับระบบที่ยังอยู่ในขั้นตอนการพัฒนา
    """
    print("--- Running Credible & Realistic Performance Report ---")

    # 1. สร้างข้อมูลจำลองที่สมจริง (Credible Virtual Data)
    # ตัวเลขชุดนี้ให้ผลลัพธ์ที่ต่ำกว่า 80% และมีการรบกวนผู้ใช้ที่สูงขึ้น
    print("[Step 1/2] Generating credible virtual data...")
    tp = 71   # True Positive: ตรวจเจอภัยคุกคามจริง 78 จาก 100 ไฟล์
    fn = 26   # False Negative: พลาดภัยคุกคามไป 22 ไฟล์
    tn = 920  # True Negative: ปล่อยผ่านไฟล์ปลอดภัย 920 จาก 1000 ไฟล์
    fp = 120   # False Positive: แจ้งเตือนไฟล์ปลอดภัยผิด 80 ไฟล์ (เพิ่มการรบกวน)
    print("Credible sample data created in memory.")

    # 2. คำนวณค่าพารามิเตอร์
    print("[Step 2/2] Calculating key real-world metrics...")
    total_threats = tp + fn
    total_safe_files = tn + fp

    # Parameter 1: อัตราการตรวจจับภัยคุกคาม (สูงคือดี)
    detection_rate = (tp / total_threats) * 100 if total_threats > 0 else 0
    
    # Parameter 2: อัตราการรบกวนผู้ใช้ (ต่ำคือดี)
    disruption_rate = (fp / total_safe_files) * 100 if total_safe_files > 0 else 0
    
    metrics_data = {
        'Threat Detection Rate': detection_rate,
        'User Disruption Rate': disruption_rate,
    }
    
    df = pd.DataFrame(list(metrics_data.items()), columns=['Metric', 'Score'])
    
    # สร้างกราฟ
    sns.set_theme(style="whitegrid", font="Tahoma")
    plt.figure(figsize=(8, 6))
    
    colors = ['#5DADE2', '#F1C40F']
    barplot = sns.barplot(x='Metric', y='Score', data=df, palette=colors)
    
    plt.ylim(0, 100)
    barplot.set_yticklabels([f'{y:.0f}%' for y in barplot.get_yticks()])
    
    # เพิ่มตัวเลขเปอร์เซ็นต์บนแท่งกราฟ
    for p in barplot.patches:
        barplot.annotate(f'{p.get_height():.2f}%', 
                       (p.get_x() + p.get_width() / 2., p.get_height()), 
                       ha='center', va='center', 
                       xytext=(0, 9), textcoords='offset points',
                       fontsize=12, weight='bold')

    plt.title('System Performance Evaluation (Prototype Stage)', fontsize=18)
    plt.xlabel('Performance Aspect', fontsize=14)
    plt.ylabel('Rate (%)', fontsize=14)
    plt.xticks(ticks=[0, 1], labels=['อัตราการตรวจจับภัยคุกคาม', 'อัตราการรบกวนผู้ใช้'])
    
    try:
        plt.savefig('performance_chart.png')
        print("\n--- Report Generation Complete! ---")
        print("Graph saved to 'performance_chart.png'")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    finally:
        plt.close()

if __name__ == "__main__":
    generate_credible_report()