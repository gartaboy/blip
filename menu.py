#!/usr/bin/env python3
"""Простое меню для BLIP CLI: выбирайте цифры, ничего набирать вручную не нужно."""

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLI = HERE / "cli.py"
INBOX = HERE / "inbox.jsonl"
GROUPS = HERE / "groups.json"

BANNER = r"""
 ____  _     ___ ____    ____ _     ___
| __ )| |   |_ _|  _ \  / ___| |   |_ _|
|  _ \| |    | || |_) || |   | |    | |
| |_) | |___ | ||  __/ | |___| |___ | |
|____/|_____|___|_|     \____|_____|___|
        ~ tiny LAN messenger ~
"""


def run(*args, pause=True):
    """Запускает команду blip без служебных логов; Ctrl+C возвращает в меню."""
    try:
        subprocess.run([sys.executable, str(CLI), "-q", *args], cwd=HERE)
    except KeyboardInterrupt:
        print("\n(остановлено)")
    if pause:
        input("\nНажмите Enter, чтобы вернуться в меню...")


def ask(prompt, default=None):
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def identity_exists():
    base = os.environ.get("APPDATA")
    path = Path(base) / "blip-cli" / "identity.json" if base else None
    return bool(path and path.exists())


def ask_number(prompt, default=None):
    while True:
        value = ask(prompt, default)
        if value.isdigit() and 1 <= int(value) <= 64:
            return value
        print("  Введите число от 1 до 64.")


def setup_identity():
    print("\n=== Первая настройка ===")
    print("Выберите свой номер (1-64) и имя, которое увидят другие.")
    number = ask_number("Ваш номер (1-64)")
    name = ask("Ваше имя", "Me")
    run("identity", "--id", number, "--name", name, pause=False)


def change_identity():
    print("\n=== Изменить номер и имя ===")
    number = ask_number("Новый номер (1-64)")
    name = ask("Новое имя", "Me")
    run("identity", "--id", number, "--name", name)


def show_identity():
    run("identity")


def discover():
    print("\nИщем узлы в сети (около 8 секунд)...")
    run("discover", "--timeout", "8")


def load_groups():
    if not GROUPS.exists():
        return {}
    try:
        return json.loads(GROUPS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_groups(groups):
    GROUPS.write_text(json.dumps(groups, ensure_ascii=False, indent=2), encoding="utf-8")


def find_peer_ids():
    """Все номера, которые сейчас видны в сети (кроме себя)."""
    try:
        out = subprocess.run(
            [sys.executable, str(CLI), "-q", "discover", "--timeout", "8", "--json"],
            cwd=HERE, capture_output=True, text=True, encoding="utf-8",
        ).stdout
        data = json.loads(out)
    except (ValueError, OSError):
        return []
    me = data.get("self", {}).get("blipId")
    return [p["blipId"] for p in data.get("peers", []) if p.get("blipId") != me]


def send_to_many(ids, text):
    """Отправляет текст каждому номеру по очереди; ошибки одного не останавливают остальных."""
    for peer in ids:
        print(f"  -> #{peer}", end=" ", flush=True)
        result = subprocess.run(
            [sys.executable, str(CLI), "-q", "send", "--peer", str(peer), "--text", text],
            cwd=HERE, capture_output=True, text=True, encoding="utf-8",
        )
        print("отправлено" if result.returncode == 0 else "не доставлено")


def group_send():
    groups = load_groups()
    if not groups:
        print("\nГрупп пока нет. Создайте группу в пункте «Управление группами».")
        input("Enter...")
        return
    names = list(groups)
    for i, name in enumerate(names, 1):
        print(f"  {i}. {name} ({', '.join(map(str, groups[name]))})")
    choice = ask("Номер группы")
    if not (choice.isdigit() and 1 <= int(choice) <= len(names)):
        print("  Нет такой группы.")
        input("Enter...")
        return
    text = ask("Текст сообщения")
    if not text:
        print("  Пустое сообщение не отправляется.")
        input("Enter...")
        return
    send_to_many(groups[names[int(choice) - 1]], text)
    input("\nНажмите Enter, чтобы вернуться в меню...")


def broadcast_all():
    print("\nИщем всех в сети (около 8 секунд)...")
    ids = find_peer_ids()
    if not ids:
        print("В сети никого не нашли.")
        input("Enter...")
        return
    print(f"Найдено: {', '.join(f'#{i}' for i in ids)}")
    text = ask("Текст для всех")
    if not text:
        print("  Пустое сообщение не отправляется.")
        input("Enter...")
        return
    send_to_many(ids, text)
    input("\nНажмите Enter, чтобы вернуться в меню...")


def manage_groups():
    while True:
        groups = load_groups()
        print("\n=== Группы ===")
        for name, ids in groups.items():
            print(f"  {name}: {', '.join(map(str, ids))}")
        print("  1. Создать группу")
        print("  2. Удалить группу")
        print("  3. Назад")
        choice = ask("Выберите")
        if choice == "1":
            name = ask("Название группы")
            if not name:
                continue
            raw = ask("Номера участников через запятую (например 2,3,5)")
            ids = sorted({int(x) for x in raw.replace(" ", "").split(",") if x.isdigit() and 1 <= int(x) <= 64})
            if not ids:
                print("  Нужен хотя бы один номер от 1 до 64.")
                continue
            groups[name] = ids
            save_groups(groups)
            print(f"  Группа «{name}» сохранена.")
        elif choice == "2":
            name = ask("Название группы для удаления")
            if groups.pop(name, None) is not None:
                save_groups(groups)
                print("  Удалено.")
            else:
                print("  Такой группы нет.")
        else:
            return


def send():
    peer = ask_number("Номер получателя (1-64)")
    text = ask("Текст сообщения")
    if not text:
        print("  Пустое сообщение не отправляется.")
        input("Enter...")
        return
    ip = ask("IP получателя (можно пусто — тогда ищем в сети)", "")
    args = ["send", "--peer", peer, "--text", text]
    if ip:
        args += ["--peer-ip", ip]
    run(*args)


def listen():
    print(f"\nСлушаем входящие. Новые сообщения пишутся в: {INBOX}")
    print("Чтобы остановить, нажмите Ctrl+C.")
    run("listen", "--output", str(INBOX))


def show_inbox():
    if not INBOX.exists():
        print("\nВходящих пока нет.")
    else:
        print(f"\n--- Входящие ({INBOX}) ---")
        print(INBOX.read_text(encoding="utf-8"))
    input("Enter, чтобы вернуться...")


MENU = [
    ("Отправить сообщение", send),
    ("Показать, кто в сети", discover),
    ("Написать группе", group_send),
    ("Написать всем в сети", broadcast_all),
    ("Управление группами", manage_groups),
    ("Слушать входящие сообщения", listen),
    ("Показать входящие", show_inbox),
    ("Изменить номер и имя", change_identity),
    ("Показать мои настройки", show_identity),
    ("Выход", None),
]


def main():
    print(BANNER)
    if not identity_exists():
        setup_identity()

    while True:
        print("\n========== BLIP CLI ==========")
        for i, (title, _) in enumerate(MENU, 1):
            print(f"  {i}. {title}")
        choice = input("Выберите действие (цифра): ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(MENU)):
            print("  Введите цифру из списка.")
            continue
        _, action = MENU[int(choice) - 1]
        if action is None:
            print("До встречи!")
            return
        action()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nДо встречи!")
