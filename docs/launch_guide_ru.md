# PreVisor: запуск (RU)

Актуальная инструкция по установке, запуску и настройке находится в `README.md`.

Короткая памятка для real‑режима (Windows):
- Установи Npcap и запускай PowerShell **от имени администратора**.
- Запусти `python app.py` и открой `http://127.0.0.1:5000/dashboard`.
- Интерфейс можно выбрать в UI или через `GET /interfaces`.

Telegram:
- Пользователь должен написать боту `/start`.
- Если нужно быстро определить `chat_id`: `python scripts/telegram_pairing.py --write`.
- Если бот не отвечает на команды, проверь webhook: `GET /telegram/webhook_info` (и при необходимости `POST /telegram/delete_webhook`).
