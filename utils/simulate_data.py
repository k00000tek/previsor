from faker import Faker
import pandas as pd
import random

fake = Faker()
data = []
for _ in range(1000):  # 1000 записей для теста
    data.append({
        'timestamp': fake.date_time_this_year(),
        'source_ip': fake.ipv4(),
        'port': random.randint(1, 65535),
        'packet_count': random.randint(1, 1000),  # Для DDoS-симуляции
        'http_method': random.choice(['GET', 'POST', 'Suspicious'])
    })
df = pd.DataFrame(data)
df.to_csv('data/simulated_traffic.csv', index=False)