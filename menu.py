#!/usr/bin/env python3
"""Простое меню для BLIP CLI: выбирайте цифры, ничего набирать вручную не нужно."""

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLI = HERE / "cli.py"
INBOX = HERE / "inbox.jsonl"


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
    ("Слушать входящие сообщения", listen),
    ("Показать входящие", show_inbox),
    ("Изменить номер и имя", change_identity),
    ("Показать мои настройки", show_identity),
    ("Выход", None),
]


def main():
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
