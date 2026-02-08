#!/usr/bin/env python
"""Утилита для "привязки" Telegram-чата к PreVisor.

Сценарий:
1) Вы создаёте бота через @BotFather и получаете TELEGRAM_BOT_TOKEN.
2) Пользователь пишет боту /start (или добавляет бота в группу и пишет любое сообщение).
3) Вы запускаете этот скрипт — он читает getUpdates и показывает chat_id.
4) Скрипт опционально запишет TELEGRAM_CHAT_ID в .env.

Так как PreVisor на Windows обычно работает локально без публичного HTTPS,
webhook Telegram использовать неудобно. Поэтому pairing делается через getUpdates.
"""

from __future__ import annotations

import argparse
import os
from typing import Optional

from utils.notifications import extract_chat_candidates, fetch_telegram_updates


def _parse_args() -> argparse.Namespace:
    """Парсит аргументы CLI.

    Returns:
        argparse.Namespace.
    """
    p = argparse.ArgumentParser(description="PreVisor Telegram pairing helper")
    p.add_argument("--env-file", default=".env", help="Путь к .env (если нужно записать TELEGRAM_CHAT_ID)")
    p.add_argument("--write", action="store_true", help="Записать TELEGRAM_CHAT_ID в env-file")
    p.add_argument("--chat-id", default=None, help="Явно выбрать chat_id (если кандидатов несколько)")
    p.add_argument("--limit", type=int, default=50, help="Сколько updates запросить")
    return p.parse_args()


def _write_env_value(env_path: str, key: str, value: str) -> None:
    """Записывает ключ/значение в .env.

    Args:
        env_path: Путь к .env.
        key: Имя переменной.
        value: Значение.
    """
    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()

    out = []
    replaced = False
    for line in lines:
        if not line.strip() or line.strip().startswith("#"):
            out.append(line)
            continue
        if line.split("=", 1)[0].strip() == key:
            out.append(f"{key}={value}")
            replaced = True
        else:
            out.append(line)

    if not replaced:
        out.append(f"{key}={value}")

    with open(env_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


def main() -> int:
    """Выполняет pairing для Telegram и выводит chat_id.

    Returns:
        Код завершения.
    """
    args = _parse_args()

    try:
        updates = fetch_telegram_updates(limit=args.limit)
    except Exception as exc:
        print(f"Ошибка Telegram API: {exc}")
        print("Подсказка: если у бота активирован webhook, polling через getUpdates работать не будет.")
        print("Проверь: GET /telegram/webhook_info (в запущенном PreVisor) или отключи webhook через deleteWebhook.")
        return 3
    candidates = extract_chat_candidates(updates)

    if not candidates:
        print("Не найдено ни одного chat_id. Проверьте:")
        print("- TELEGRAM_BOT_TOKEN задан")
        print("- вы написали боту /start или добавили бота в группу и отправили сообщение")
        return 2

    print("Найденные чаты (chat_id -> name):")
    for cid, name in candidates:
        print(f"  {cid} -> {name}")

    selected: Optional[str] = args.chat_id
    if selected is None:
        selected = candidates[-1][0]

    print(f"\nВыбранный TELEGRAM_CHAT_ID: {selected}")

    if args.write:
        _write_env_value(args.env_file, "TELEGRAM_CHAT_ID", selected)
        print(f"Записано в {args.env_file}: TELEGRAM_CHAT_ID={selected}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
