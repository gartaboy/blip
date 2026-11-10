"""Точка входа для exe-сборки.

- Без аргументов (двойной щелчок) — открывает меню.
- С аргументом ``--cli`` — работает как обычный CLI: ``blip-cli.exe --cli send ...``.
"""

import sys


def _run_cli(argv):
    from blip_cli.cli import main
    return main(argv)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        raise SystemExit(_run_cli(sys.argv[2:]))

    import menu
    try:
        menu.main()
    except (KeyboardInterrupt, EOFError):
        print("\nДо встречи!")
