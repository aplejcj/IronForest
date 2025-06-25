import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

RESULTS_CSV = "./experiment_results.csv"

def main():
    try:
        # อ่านข้อมูลด้วย pandas
        df = pd.read_csv(RESULTS_CSV)
    except FileNotFoundError:
        print(f"Error: '{RESULTS_CSV}' not found. Please run the experiment first.")
        return
        
    if df.empty:
        print("Error: The results file is empty.")
        return

    # คำนวณค่าสถิติ
    time_data = df['time_to_immunise_seconds']
    mean_time = time_data.mean()
    median_time = time_data.median()
    min_time = time_data.min()
    max_time = time_data.max()

    print("--- Experiment Results ---")
    print(f"Mean Time to Immunise:   {mean_time:.4f} s")
    print(f"Median Time to Immunise: {median_time:.4f} s")
    print(f"Min Time:                {min_time:.4f} s")
    print(f"Max Time:                {max_time:.4f} s")
    
    # ตั้งค่าสไตล์ของกราฟให้ดูสวยงาม
    sns.set_theme(style="whitegrid")

    # 1. สร้างกราฟ Histogram แสดงการกระจายตัวของเวลา
    plt.figure(figsize=(10, 6))
    sns.histplot(time_data, bins=10, kde=True)
    plt.title('Distribution of Time-to-Immunise (n=30)', fontsize=16)
    plt.xlabel('Time (seconds)', fontsize=12)
    plt.ylabel('Frequency', fontsize=12)
    plt.axvline(mean_time, color='r', linestyle='--', label=f'Mean: {mean_time:.2f}s')
    plt.legend()
    plt.savefig('histogram_results.png') # บันทึกเป็นไฟล์ภาพ
    print("\nSaved histogram plot to 'histogram_results.png'")

    # 2. สร้างกราฟ Box Plot เพื่อดูค่าทางสถิติ
    plt.figure(figsize=(8, 6))
    sns.boxplot(y=time_data)
    plt.title('Box Plot of Time-to-Immunise (n=30)', fontsize=16)
    plt.ylabel('Time (seconds)', fontsize=12)
    plt.savefig('boxplot_results.png') # บันทึกเป็นไฟล์ภาพ
    print("Saved box plot to 'boxplot_results.png'")

if __name__ == "__main__":
    main()