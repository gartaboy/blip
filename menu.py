#!/usr/bin/env python3
"""Простое меню для BLIP CLI: выбирайте цифры, ничего набирать вручную не нужно."""

import json
import os
import subprocess
import sys
import threading
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


# --- helpers -----------------------------------------------------------------

def blip(*args, capture=False):
    """Запускает cli.py без служебных логов."""
    return subprocess.run(
        [sys.executable, str(CLI), "-q", *args],
        cwd=HERE, capture_output=capture, text=True, encoding="utf-8",
    )


def ask(prompt, default=None):
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def ask_number(prompt, default=None):
    while True:
        value = ask(prompt, default)
        if value.isdigit() and 1 <= int(value) <= 64:
            return value
        print("  Введите число от 1 до 64.")


def pause():
    input("\nEnter — назад в меню...")


def identity_exists():
    base = os.environ.get("APPDATA")
    return bool(base) and (Path(base) / "blip-cli" / "identity.json").exists()


# --- groups storage ----------------------------------------------------------

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
    """Номера всех, кто сейчас в сети (кроме себя)."""
    try:
        data = json.loads(blip("discover", "--timeout", "8", "--json", capture=True).stdout)
    except ValueError:
        return []
    me = data.get("self", {}).get("blipId")
    return [p["blipId"] for p in data.get("peers", []) if p.get("blipId") != me]


def send_to_many(ids, text):
    """Каждому по очереди; ошибка одного не останавливает остальных."""
    for peer in ids:
        ok = blip("send", "--peer", str(peer), "--text", text, capture=True).returncode == 0
        print(f"  #{peer}: {'отправлено' if ok else 'не доставлено'}")


# --- actions -----------------------------------------------------------------

def live_chat():
    """Чат с одним человеком: входящие появляются сразу, внизу строка ответа."""
    peer = ask_number("С каким номером общаемся (1-64)")
    print(f"\n=== Чат с #{peer} === (напишите /выход, чтобы закрыть)\n")
    stop = threading.Event()

    def reader():
        proc = subprocess.Popen(
            [sys.executable, str(CLI), "-q", "listen", "--output", str(INBOX), "--json"],
            cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8",
        )
        try:
            for line in proc.stdout:
                if stop.is_set():
                    break
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("event") != "message":
                    continue
                sender = event.get("from")
                label = f"#{sender}" if sender == int(peer) else f"(#{sender})"
                print(f"\r{label}: {event.get('text', '')}\n> ", end="", flush=True)
        finally:
            proc.terminate()

    threading.Thread(target=reader, daemon=True).start()
    try:
        while True:
            text = input("> ").strip()
            if text == "/выход":
                break
            if text:
                blip("send", "--peer", peer, "--text", text, capture=True)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        stop.set()
    print("\nЧат закрыт.")


def create_group(groups):
    name = ask("Название группы")
    if not name:
        return
    raw = ask("Номера участников через запятую (например 2,3,5)")
    ids = sorted({int(x) for x in raw.replace(" ", "").split(",")
                  if x.isdigit() and 1 <= int(x) <= 64})
    if not ids:
        print("  Нужен хотя бы один номер от 1 до 64.")
        return
    groups[name] = ids
    save_groups(groups)
    print(f"  Группа «{name}» сохранена.")


def write_to():
    """Один экран: выбрать группу, всех в сети, создать или удалить группу."""
    groups = load_groups()
    names = list(groups)
    print("\n  a. Всем в сети")
    for i, name in enumerate(names, 1):
        print(f"  {i}. {name} ({', '.join(map(str, groups[name]))})")
    print("  n. Создать группу" + ("   d. Удалить группу" if names else ""))
    choice = ask("Кому (цифра, a, n, d)")

    if choice == "n":
        create_group(groups)
        return
    if choice == "d" and names:
        num = ask("Номер группы для удаления")
        if num.isdigit() and 1 <= int(num) <= len(names):
            del groups[names[int(num) - 1]]
            save_groups(groups)
            print("  Удалено.")
        return
    if choice == "a":
        print("\nИщем всех в сети (около 8 секунд)...")
        ids = find_peer_ids()
    elif choice.isdigit() and 1 <= int(choice) <= len(names):
        ids = groups[names[int(choice) - 1]]
    else:
        print("  Нет такого пункта.")
        return
    if not ids:
        print("  Никого не нашли.")
        return

    text = ask("Текст сообщения")
    if not text:
        print("  Пустое сообщение не отправляется.")
        return
    send_to_many(ids, text)
    pause()


def discover():
    print("\nИщем узлы в сети (около 8 секунд)...")
    blip("discover", "--timeout", "8")
    pause()


def inbox():
    """Показывает последние входящие, затем слушает новые (Ctrl+C — назад)."""
    if INBOX.exists():
        lines = INBOX.read_text(encoding="utf-8").splitlines()[-20:]
        print("\n--- Последние входящие ---")
        for line in lines:
            try:
                e = json.loads(line)
                print(f"#{e.get('from')}: {e.get('text')}")
            except ValueError:
                pass
    print("\nСлушаем новые сообщения. Ctrl+C — назад.")
    try:
        blip("listen", "--output", str(INBOX))
    except KeyboardInterrupt:
        pass


def settings():
    print()
    blip("identity")
    if ask("Изменить номер и имя? (y — да, Enter — назад)").lower() == "y":
        number = ask_number("Новый номер (1-64)")
        name = ask("Новое имя", "Me")
        blip("identity", "--id", number, "--name", name)


def setup_identity():
    print("\n=== Первая настройка ===")
    number = ask_number("Ваш номер (1-64)")
    name = ask("Ваше имя", "Me")
    blip("identity", "--id", number, "--name", name)


# --- menu --------------------------------------------------------------------

MENU = [
    ("Чат с человеком", live_chat),
    ("Написать группе или всем", write_to),
    ("Кто в сети", discover),
    ("Входящие", inbox),
    ("Настройки", settings),
    ("Выход", None),
]


def main():
    print(BANNER)
    if not identity_exists():
        setup_identity()

    while True:
        print("\n=== BLIP CLI ===")
        for i, (title, _) in enumerate(MENU, 1):
            print(f"  {i}. {title}")
        choice = input("Цифра: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(MENU)):
            print("  Введите цифру из списка.")
            continue
        _, action = MENU[int(choice) - 1]
        if action is None:
            return
        action()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nДо встречи!")
