import os
from celery import Celery
from modules.data_collector import collect_traffic  # Импорт твоей функции
from config import MODE, COLLECTION_INTERVAL, CELERY_BROKER_URL, DATA_DIR  # Из config.py
from modules.preprocessor import preprocess_data
from config import PROCESSED_DATA_DIR
from modules.analyzer import Analyzer
from modules.database import save_alert
from utils.notifications import notify_new_alert
import logging

# Создаём Celery app
celery = Celery('previsor',
                broker=CELERY_BROKER_URL,
                include=['celery_app'])  # include для задач в этом файле

# Задача для сбора данных
@celery.task
def scheduled_collect():
    df = collect_traffic(mode=MODE)
    # Определяем имя файла по MODE
    filename_map = {
        'real': 'collected_traffic.csv',
        'simulated': 'simulated_traffic.csv',
        'test': 'test_traffic.csv',
    }
    raw_name = filename_map.get(MODE, 'collected_traffic.csv')
    input_path = os.path.join('data', raw_name)
    df.to_csv(input_path, index=False)

    preprocess_data(input_path, output_dir=PROCESSED_DATA_DIR)
    return "Сбор и предобработка завершены"

# Настройка beat-schedule (цикл каждые COLLECTION_INTERVAL сек)
# celery.conf.beat_schedule = {
#     'collect-every-interval': {
#         'task': 'celery_app.scheduled_collect',
#         'schedule': COLLECTION_INTERVAL,  # Из config.py (600 для 10 мин)
#     },
# }

@celery.task
def full_pipeline():
    try:
        # 1. Сбор
        df_raw = collect_traffic(mode=MODE, include_labels=False)

        filename_map = {
            'real': 'collected_traffic.csv',
            'simulated': 'simulated_traffic.csv',
            'test': 'test_traffic.csv'
        }
        raw_name = filename_map.get(MODE, 'collected_traffic.csv')
        raw_path = os.path.join(DATA_DIR, raw_name)
        df_raw.to_csv(raw_path, index=False)


        # 2. Предобработка
        result = preprocess_data(raw_path, output_dir=DATA_DIR)
        processed_name = raw_name.replace('.csv', '_processed.csv')
        processed_path = os.path.join(DATA_DIR, processed_name)
        result['processed_df'].to_csv(processed_path, index=False)
        df_processed = result['processed_df']

        # 3. Анализ
        X = result['X_test'] if result['X_test'] is not None else result['X_train']

        if X is None or len(X) == 0:
            return "Нет данных для анализа"

        # Берём IP только для тех строк, которые реально в X
        source_ips = None
        if 'source_ip' in df_processed.columns:
            # Индексы X — подмножество исходных индексов df_processed
            # Привязываем source_ip по индексу
            source_ips = df_processed.loc[X.index, 'source_ip'].tolist()
        # На всякий случай убираем source_ip из X, если он есть
        X_no_ip = X.drop(columns=['source_ip'], errors='ignore')

        analyzer = Analyzer(model_type='rf')
        analyzer.model_path = 'models/previsor_model.pkl'
        alerts = analyzer.analyze(X_no_ip.values, source_ips=source_ips)

        # 4. Сохранение
        new_alerts = 0
        for a in alerts:
            if a['alert']:
                save_alert(a['type'], a['probability'], a.get('source_ip'))
                notify_new_alert(a['type'], a['probability'], a.get('source_ip'))
                new_alerts += 1

        logging.info(f"Автопайплайн завершён: {new_alerts} новых алертов")
        return f"Успех: {new_alerts} алертов"
    except Exception as e:
        logging.error(f"Автопайплайн ошибка: {e}")
        return f"Ошибка: {e}"

# Beat schedule
celery.conf.beat_schedule = {
    'full-pipeline-every-10min': {
        'task': 'celery_app.full_pipeline',
        'schedule': COLLECTION_INTERVAL,
    },
}