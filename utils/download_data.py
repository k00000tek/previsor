import os
import subprocess
import zipfile
import pandas as pd

def download_file_with_kaggle(dataset_name: str, dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    zip_name = dataset_name.split("/")[-1] + ".zip"
    zip_path = os.path.join(dest_dir, zip_name)
    if not os.path.exists(zip_path):
        cmd = ["kaggle", "datasets", "download", "-d", dataset_name, "-p", dest_dir]
        print("Запуск:", " ".join(cmd))
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print("Ошибка скачивания:", res.stderr)
            raise RuntimeError(f"Не удалось скачать {dataset_name}")
        print("Скачано:", zip_path)
    else:
        print("Архив уже существует:", zip_path)
    return zip_path

def extract_zip_python(zip_path: str, extract_to: str):
    print(f"Распаковываю (Python) {zip_path} → {extract_to}")
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(extract_to)
    print("Распаковка завершена.")

def sample_and_save(df: pd.DataFrame, n: int, label_col: str = None, out_path: str = None) -> pd.DataFrame:
    if label_col and (label_col in df.columns):
        classes = df[label_col].unique()
        per_class = max(1, n // len(classes))
        parts = []
        for c in classes:
            df_c = df[df[label_col] == c]
            if len(df_c) <= per_class:
                parts.append(df_c)
            else:
                parts.append(df_c.sample(per_class, random_state=42))
        df_sample = pd.concat(parts, ignore_index=True)
        if len(df_sample) < n:
            remaining = df.drop(df_sample.index, errors='ignore')
            needed = n - len(df_sample)
            if len(remaining) > 0:
                extra = remaining.sample(min(needed, len(remaining)), random_state=42)
                df_sample = pd.concat([df_sample, extra], ignore_index=True)
    else:
        if len(df) > n:
            df_sample = df.sample(n, random_state=42)
        else:
            df_sample = df.copy()
    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        df_sample.to_csv(out_path, index=False)
        print("Сохранено подвыборанное:", out_path)
    return df_sample

def process_dataset(dataset_identifier: str, target_rows: int, label_col: str = None, hint_name: str = None, base_output_dir: str = "../data"):
    print("\n=== Обработка датасета:", dataset_identifier, "===")
    tmp_dir = "tmp_kaggle"
    os.makedirs(tmp_dir, exist_ok=True)

    # 1. Скачать архив
    zip_path = download_file_with_kaggle(dataset_identifier, dest_dir=tmp_dir)

    # 2. Распаковать
    extract_zip_python(zip_path, tmp_dir)

    # 3. Найти CSV файлы
    csv_paths = []
    for root, dirs, files in os.walk(tmp_dir):
        for f in files:
            if f.lower().endswith(".csv"):
                csv_paths.append(os.path.join(root, f))
    if not csv_paths:
        raise FileNotFoundError(f"CSV файлы не найдены в распакованной папке {tmp_dir} для {dataset_identifier}")
    csv_path = csv_paths[0]
    print("Выбран CSV:", csv_path)

    # 4. Читаем CSV
    df = pd.read_csv(csv_path, low_memory=False)
    print("\nИнформация (info):")
    print(df.info())
    print("\nПервые 5 строк:")
    print(df.head(5))

    # 5. Подвыборка и сохранение
    hint = hint_name or dataset_identifier.split("/")[-1]
    out_filename = f"{hint}_sample.csv"
    out_full_path = os.path.abspath(os.path.join(os.getcwd(), os.pardir, "data", out_filename))
    df_sample = sample_and_save(df, target_rows, label_col=label_col, out_path=out_full_path)

    # 6. Удалить полные CSV-файлы
    for path in csv_paths:
        try:
            os.remove(path)
            print("Удалён оригинальный CSV:", path)
        except Exception as e:
            print("Не удалось удалить CSV:", path, ":", e)

    return df, df_sample

def main():
    configs = [
        ("ericanacletoribeiro/cicids2017-cleaned-and-preprocessed", 12000, "Attack Type", "cicids2017"),
        ("ispangler/csic-2010-web-application-attacks", 5000, "classification", "csic2010"),
        ("drjamailalsawwa/mscad", 10000, "Label", "mscad")
    ]
    base_out = os.path.abspath(os.path.join(os.getcwd(), os.pardir, "data"))
    for ds_id, n_rows, lbl, hint in configs:
        try:
            process_dataset(ds_id, n_rows, label_col=lbl, hint_name=hint, base_output_dir=base_out)
        except Exception as e:
            print("Ошибка при обработке", ds_id, ":", e)

if __name__ == "__main__":
    main()