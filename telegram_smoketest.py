#!/usr/bin/env python3
import os
import sys
import json
import requests


API = "https://api.telegram.org/bot{token}/{method}"
TELEGRAM_BOT_TOKEN="8478758709:AAHeApTfPirUh7dcjzxxa2fxqOW5CwKxexo"
TELEGRAM_CHAT_ID="-1005026845212"

def tg_call(token: str, method: str, payload: dict | None = None) -> dict:
    url = API.format(token=token, method=method)
    r = requests.post(url, json=payload or {}, timeout=15)
    try:
        data = r.json()
    except Exception:
        raise SystemExit(f"Telegram API вернул не-JSON ответ: HTTP {r.status_code}\n{r.text}")

    if not r.ok or not data.get("ok"):
        raise SystemExit(f"Ошибка Telegram API: HTTP {r.status_code}\n{json.dumps(data, ensure_ascii=False, indent=2)}")

    return data


def main() -> None:
    token = "8478758709:AAHeApTfPirUh7dcjzxxa2fxqOW5CwKxexo"
    if not token:
        raise SystemExit("Нет TELEGRAM_BOT_TOKEN в окружении.")

    # Удобно, если ранее ставили webhook (иначе getUpdates может не работать).
    tg_call(token, "deleteWebhook", {"drop_pending_updates": True})

    # Режим 1: отправка сообщения (нужен TELEGRAM_CHAT_ID)
    if len(sys.argv) >= 2 and sys.argv[1] != "--get-chat-id":
        chat_id = "-5026845212"
        if not chat_id:
            raise SystemExit("Нет TELEGRAM_CHAT_ID в окружении. Запусти с --get-chat-id или укажи chat_id вручную.")

        text = " ".join(sys.argv[1:]).strip()
        data = tg_call(token, "sendMessage", {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": True
        })
        msg_id = data["result"]["message_id"]
        print(f"OK: сообщение отправлено. message_id={msg_id}")
        return

    # Режим 2: вывести chat_id из последних апдейтов
    data = tg_call(token, "getUpdates", {"limit": 50, "timeout": 0})
    updates = data.get("result", [])
    if not updates:
        print("Апдейтов нет. Напиши любое сообщение в группе, где есть бот, и повтори.")
        return

    seen = {}
    for u in updates:
        msg = u.get("message") or u.get("channel_post") or {}
        chat = msg.get("chat") or {}
        cid = chat.get("id")
        title = chat.get("title") or chat.get("username") or chat.get("first_name") or "unknown"
        ctype = chat.get("type")
        if cid is not None:
            seen[cid] = (title, ctype)

    if not seen:
        print("Не нашёл chat_id в апдейтах (возможно, бот не видит сообщения из группы).")
        return

    print("Найденные чаты (chat_id -> title/type):")
    for cid, (title, ctype) in seen.items():
        print(f"  {cid} -> {title} ({ctype})")


if __name__ == "__main__":
    main()
