"""Точка входу ЛР №2: команди ``demo`` (Завдання 1) та ``analyze`` (Завдання 2).

Запуск з кореня репозиторію: ``python -m labs.lab02.main demo`` або
``python -m labs.lab02.main analyze --targets <файл>``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from labs.lab02 import task1, task2

EXIT_INTERRUPTED = 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="Лабораторна робота №2 (варіант 5)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("demo", help="Завдання 1: демонстрація ООП-моделі")

    analyze = subparsers.add_parser(
        "analyze", help="Завдання 2 (варіант 5): сканер доступності сервісів"
    )
    task2.add_arguments(analyze)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "demo":
            task1.run_demo()
            return 0
        return task2.run(args)
    except KeyboardInterrupt:
        print("\n[WARNING] Interrupted by user", file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
