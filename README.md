# PreVisor — мониторинг сетевых угроз и аномалий

PreVisor — веб‑приложение для предиктивного мониторинга IT‑инфраструктуры: захват сетевого трафика, выявление угроз (ML + эвристики), хранение событий в БД и уведомления в Telegram.

## Типы алертов
- `Suspicious Port` — повторяющиеся обращения к типичным «рискованным» портам.
- `Port Scanning` — много уникальных портов от одного источника за короткий интервал.
- `DDoS` — всплеск пакетов от множества источников к одной цели.
- `HTTP Anomaly` — подозрительные HTTP‑паттерны (инъекции, traversal и т.п.).
- `Anomaly` — нетипичное поведение трафика относительно привычного baseline (возможная новая/редкая угроза или сбой).

## Требования (Windows, real‑режим)
- Python 3.12+ и PowerShell.
- Для захвата трафика нужен Npcap (желательно режим совместимости с WinPcap).
- Для sniff реального трафика PowerShell должен быть запущен **от имени администратора**.

## Установка
```powershell
git clone https://github.com/k00000tek/previsor
cd previsor
python -m venv .venv
.\.venv\Scripts\Activate
pip install -r requirements.txt
```

## Конфигурация (.env)
Создай `.env` (можно взять за основу `.env.example`) и задай минимум:
```ini
PREVISOR_NET_IFACE=auto
PREVISOR_TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
```

## Запуск
```powershell
python app.py
```
Проверка:
```powershell
Invoke-RestMethod http://127.0.0.1:5000/health
```
UI: `http://127.0.0.1:5000/dashboard`

Время в UI отображается в формате `MSK (UTC+3)`.

## Telegram
Чтобы получать уведомления, пользователь должен написать боту `/start` (в личку или в группе).

Команды бота включены по умолчанию (отключение: `PREVISOR_TELEGRAM_COMMANDS=false`):
- `/start` или `/help` — меню и описание.
- `/selectchat` — привязать текущий чат для уведомлений.
- `/status` — статус непрерывного мониторинга.
- `/startmonitor` и `/stopmonitor` — управление мониторингом.
Команды обрабатываются самим приложением, поэтому `app.py` должен быть запущен.
В группах Telegram команда может прийти как `/selectchat@BotName` — это поддерживается.

Если команды не работают (например, бот не отвечает на `/start`), проверьте webhook:
- `GET /telegram/webhook_info` (dev endpoint) — если `result.url` не пустой, polling через `getUpdates` не будет работать.
- Отключение webhook (dev): `POST /telegram/delete_webhook` (по умолчанию удаляет pending updates).
- Диагностический тест Telegram API: `PREVISOR_RUN_TELEGRAM_DEBUG=true pytest -k telegram_bot_api_debug -s`.

## Baseline и аномалии (IsolationForest)
В real‑режиме baseline пополняется автоматически и используется для обучения/дообучения детектора аномалий.
Baseline берётся из БД (`traffic_logs`), поэтому runtime‑CSV не раздувается бесконечным append.
Записи, связанные с алертами, исключаются из baseline‑пула; если алерт помечен как `false_positive`, запись снова становится baseline‑кандидатом.

Ключевые параметры:
- `PREVISOR_BASELINE_TARGET_ROWS=5000` — минимальный размер baseline для первого обучения.
- `PREVISOR_ANOMALY_RETRAIN_ROWS=5000` — дообучение после прироста baseline на N строк с момента последнего обучения.
- `PREVISOR_ANOMALY_STRATEGY=baseline` и `PREVISOR_ANOMALY_BASELINE_QUANTILE=0.999` — порог аномальности относительно baseline‑статистики.
- Для накопления baseline в БД должно быть включено логирование трафика: `PREVISOR_LOG_TRAFFIC=true`.

## Эмуляция угроз
См. `docs/threat_emulation_ru.md` (все команды выполняй только на своем ПК и в своей сети).

## API (основное)
- `GET /health`
- `GET /interfaces`
- `POST /analyze?mode=real&model=rf`
- `GET /alerts?limit=50`
- `GET /monitor/status`, `POST /monitor/start`, `POST /monitor/stop`
- `POST /settings/interface` — смена `PREVISOR_NET_IFACE` (сохранение в `.env`)
- `GET /telegram/status`
- `GET /traffic_logs/<id>` — детальная запись по трафику для алерта (через `traffic_log_id`)

## Структура проекта
```text
previsor/
  app.py                - Flask-приложение: API, дашборд, мониторинг (threads/queue), Telegram-команды
  config.py             - конфигурация и дефолты (env), пути к данным/моделям
  requirements.txt      - зависимости Python
  .env.example          - пример минимальной конфигурации
  pytest.ini            - настройки pytest для текущего окружения

  modules/              - ядро системы
    database.py         - SQLite схема и функции доступа (alerts, traffic_logs, ip_cache)
    data_collector.py   - сбор трафика (real) и источники demo/test/dataset
    preprocessor.py     - предобработка и feature engineering (train/inference)
    analyzer.py         - классификация угроз (RF/XGB), расчёт риска, TI-обогащение
    heuristics.py       - эвристические детекторы и поддержка эмуляции
    anomaly_detector.py - детектор аномалий (IsolationForest) и baseline-статистика
    baseline_manager.py - baseline из БД и авто-обучение/дообучение IF
    pipeline.py         - единый пайплайн: collect -> preprocess -> detect -> alerts

  utils/                - инфраструктурные модули
    notifications.py    - Telegram: отправка уведомлений, polling/webhook утилиты
    api_integration.py  - Threat Intelligence (AbuseIPDB) + кэширование в БД
    download_data.py    - скачивание датасетов через Kaggle CLI (формирование data/samples)
    process_data.py     - подготовка processed-датасетов (data/runtime/datasets)

  templates/            - HTML-шаблоны
    dashboard.html      - дашборд (UI, управление мониторингом, настройки)

  static/               - статические файлы и диаграммы
    previsor_*_diagram.* - PlantUML диаграммы (puml + png)
    previsor_er_diagram.* - ER-диаграмма (puml + png)
    info_*.puml          - справочные диаграммы для ВКР

  tests/                - тесты (pytest)
    conftest.py         - фикстуры и изоляция runtime в .tests_tmp
    test_app_endpoints.py
    test_preprocessor.py
    test_analyzer_inference.py
    test_telegram_commands_unit.py
    test_telegram_bot_api_debug.py

  docs/                 - эксплуатационная документация и материалы к защите
  scripts/              - CLI-скрипты обучения/диагностики
  data/                 - sample/runtime CSV и processed датасеты
  db/                   - runtime SQLite БД (db/runtime/previsor.db)
  models/               - модели и артефакты (pretrained/ и runtime/)
  notebooks/            - исследовательские ноутбуки (EDA)
  results/              - сохранённые результаты прогонов
  docx/                 - материалы ВКР (задание/текст)
```
Локальные директории окружения (`.venv/`, `__pycache__/`, `.pytest_cache/`, `.idea/`) в структуру проекта не входят.

## Доп. документы
- `docs/defense_pack_ru.md` — чек‑лист подготовки к защите.
- `docs/powershell_scenarios.md` — сценарии PowerShell.
- Диаграммы PlantUML: `static/*.puml`.
- Список предобученных артефактов: `models/pretrained/MODELS_LIST.md`.
