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

## Доп. документы
- `docs/defense_pack_ru.md` — чек‑лист подготовки к защите.
- `docs/powershell_scenarios.md` — сценарии PowerShell.
- Диаграммы PlantUML: `static/*.puml`.
- Список предобученных артефактов: `models/pretrained/MODELS_LIST.md`.
