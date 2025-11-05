import os
from celery import Celery
from modules.data_collector import collect_traffic  # Импорт твоей функции
from config import MODE, COLLECTION_INTERVAL, CELERY_BROKER_URL  # Из config.py
from modules.preprocessor import preprocess_data
from config import PROCESSED_DATA_DIR

# Создаём Celery app
celery = Celery('previsor',
                broker=CELERY_BROKER_URL,
                include=['celery_app'])  # include для задач в этом файле

# Задача для сбора данных
@celery.task
def scheduled_collect():
    collect_traffic(mode=MODE)
    input_path = os.path.join('data', 'collected_traffic.csv')  # Или simulated
    preprocess_data(input_path, output_dir=PROCESSED_DATA_DIR)
    return "Сбор и предобработка завершены"

# Настройка beat-schedule (цикл каждые COLLECTION_INTERVAL сек)
celery.conf.beat_schedule = {
    'collect-every-interval': {
        'task': 'celery_app.scheduled_collect',
        'schedule': COLLECTION_INTERVAL,  # Из config.py (600 для 10 мин)
    },
}

# Для отладки: celery.conf.update(task_track_started=True) если нужно