# PreVisor: веб-система предиктивного мониторинга IT-инфраструктуры

![Python](https://img.shields.io/badge/Python-3.12-lightblue)
![Flask](https://img.shields.io/badge/Flask-3.1-lightgrey)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.7-orange)
![Celery](https://img.shields.io/badge/Celery-5.4-orange)

## Описание
PreVisor обнаруживает аномалии и сетевые угрозы по трафику с помощью ML и эвристик. Цель - раннее выявление угроз и снижение downtime в корпоративных сетях.

## Основные возможности
- Real-режим: захват трафика и анализ в фоне.
- Модели: RandomForest/XGBoost + IsolationForest (аномалии).
- Эвристики: DDoS, port scanning, подозрительные порты, HTTP-аномалии.
- Telegram-уведомления о новых алертах.
- Дашборд: фильтры, статусы, статистика.

## Быстрый старт
1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/k00000tek/previsor
   cd previsor
   ```
2. Создайте и активируйте окружение:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   .venv\Scripts\activate     # Windows
   ```
3. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```
4. Запустите сервер:
   ```bash
   python app.py
   ```
Доступ: http://127.0.0.1:5000/health

Полная инструкция (от клона до первого алерта): `docs/launch_guide_ru.md`.

Эмуляция тестовых угроз: `docs/threat_emulation_ru.md`.

Сценарии разработчика (PowerShell): `docs/test_scenarios_powershell.md`.

## Настройка Telegram
- Бот уже создан - найдите **PreVisor notifications bot**.
- Отправьте `/start` в чат, где нужны уведомления.
- Заполните `.env`:
  ```ini
  TELEGRAM_BOT_TOKEN=...
  TELEGRAM_CHAT_ID=...
  PREVISOR_TELEGRAM_ENABLED=true
  ```

## Реальный режим и выбор интерфейса
- Запускайте PowerShell от имени администратора.
- Интерфейс можно узнать через API:
  ```powershell
  Invoke-RestMethod http://127.0.0.1:5000/interfaces
  ```
- Задайте имя (пример):
  ```powershell
  $env:PREVISOR_NET_IFACE="Беспроводная сеть"
  ```
- Автоматический мониторинг включен по умолчанию (`PREVISOR_AUTO_MONITOR=true`).
- Интервал мониторинга: `PREVISOR_AUTO_MONITOR_INTERVAL` (сек, по умолчанию 300).
- Статус мониторинга: `GET /monitor/status`.

## Работа через UI
- Откройте http://127.0.0.1:5000/dashboard
- Нажмите **Запустить анализ**.
- Для baseline используйте **Собрать базовую выборку**.

## Типы угроз (кратко)
- `Suspicious Port` - повторяющиеся обращения к типичным рискованным портам.
- `Port Scanning` - множество уникальных портов от одного источника.
- `DDoS` - всплеск пакетов от большого числа источников к одной цели.
- `HTTP Anomaly` - признаки подозрительных запросов (паттерны инъекций и т.п.).
- `Anomaly` - аномалия по модели IsolationForest.

## Фоновый мониторинг
Авто-монитор работает в `app.py`:
- включение: `PREVISOR_AUTO_MONITOR=true`
- интервал: `PREVISOR_AUTO_MONITOR_INTERVAL=300`
- статус: `GET /monitor/status`

Celery можно подключить при необходимости, но для базового сценария не требуется.

## Отчеты по обучению
После обучения отчеты лежат в `models/runtime/last_report*.txt`.

Обучение классификаторов:
```powershell
python scripts/train_classifier.py --model rf
python scripts/train_classifier.py --model xgb
```

Обучение baseline для аномалий:
```powershell
python scripts/train_anomaly_baseline.py
```

## База данных и IP-репутация
- Алерты сохраняются в SQLite (таблица `alerts`).
- Кэш `ip_cache` обновляется только при наличии `ABUSEIPDB_KEY` и успешных запросах к API.

## API эндпоинты (кратко)
- `GET /health`
- `GET /interfaces`
- `POST /analyze?mode=real&model=rf`
- `GET /collect?mode=real&baseline=1&rows=200`
- `GET /alerts?limit=10`

## UI кто из пользует
- Оператор/аналитик ИБ: просмотр алертов, фильтры, статусы.
- Внутренние режимы demo/test/dataset скрыты по умолчанию (флаг `PREVISOR_ENABLE_DEV_UI=true`).

---
Разработано в рамках ВКР, 2025.
