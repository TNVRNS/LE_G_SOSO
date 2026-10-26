"""Завдання 2, варіант 5: сканер доступності мережевих сервісів.

Утиліта читає список цілей (host + port) із JSON або CSV, перевіряє
синтаксис адрес за допомогою ``re``, пробує встановити TCP-з'єднання,
класифікує результат через ``@dataclass``, друкує таблицю зі статистикою
та (за бажанням) зберігає результат у CSV. Хід роботи фіксується через
``logging``.

"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import socket
import sys
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger("lab02.scanner")

# Константи
MIN_PORT = 1
MAX_PORT = 65535
DEFAULT_TIMEOUT_SEC = 3.0
MAX_TIMEOUT_SEC = 60.0

EXIT_OK = 0
EXIT_INPUT_ERROR = 2
EXIT_OUTPUT_ERROR = 3

# Октет 0-255 без ведучих нулів (щоб "01.02.03.04" не вважався коректним).
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
IPV4_RE = re.compile(rf"{_OCTET}(?:\.{_OCTET}){{3}}", re.ASCII)
# Все, що схоже на IPv4 (4 числові групи), мусить пройти саме IPV4_RE.
DOTTED_NUMERIC_RE = re.compile(r"[0-9]+(?:\.[0-9]+){3}", re.ASCII)
# Мітка домену: 1-63 символи, літери/цифри/дефіс, без дефіса на краях.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
DOMAIN_RE = re.compile(rf"{_LABEL}(?:\.{_LABEL})*", re.ASCII)
PORT_RE = re.compile(r"[0-9]{1,6}", re.ASCII)
MAX_HOSTNAME_LEN = 253

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
}

CSV_COLUMNS = ("host", "port", "service", "status", "response_time_ms", "notes")


# Моделі даних
class Status(str, Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    INVALID = "INVALID"


@dataclass(frozen=True)
class Target:
    """Запис зі списку цілей; значення ще не перевірені (можуть бути будь-якими)."""

    host: object
    port: object


@dataclass
class ScanResult:
    """Результат перевірки однієї цілі: Host, Port, Status, ResponseTime."""

    host: str
    port: int | str
    service: str
    status: Status
    response_time_ms: float | None = None
    timed_out: bool = False
    notes: str = ""

    @property
    def response_display(self) -> str:
        if self.response_time_ms is not None:
            return f"{self.response_time_ms:.1f} ms"
        return "TIMEOUT" if self.timed_out else "-"


@dataclass(frozen=True)
class ScanStats:
    total: int
    scanned: int
    online: int
    offline: int
    invalid: int

    def percent(self, count: int) -> float:
        return 100.0 * count / self.scanned if self.scanned else 0.0


# Читання цілей
class TargetsFileError(ValueError):
    """Файл цілей має некоректний формат або структуру."""


def load_targets(path: Path) -> list[Target]:
    """Читає цілі з .json або .csv; при проблемі з файлом -> OSError/ValueError."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _load_json(path)
    if suffix == ".csv":
        return _load_csv(path)
    raise TargetsFileError(f"Unsupported file type {path.suffix!r} (use .json or .csv)")


def _load_json(path: Path) -> list[Target]:
    with path.open(encoding="utf-8") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError as exc:
            raise TargetsFileError(f"Malformed JSON: {exc}") from exc
    if not isinstance(data, list):
        raise TargetsFileError("JSON root must be a list of {host, port} objects")
    targets = []
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise TargetsFileError(f"Record #{index} is not an object")
        targets.append(Target(item.get("host"), item.get("port")))
    return targets


def _load_csv(path: Path) -> list[Target]:
    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        fields = {
            (name or "").strip().lower(): name for name in reader.fieldnames or ()
        }
        if not {"host", "port"} <= fields.keys():
            raise TargetsFileError(
                "CSV must have 'host' and 'port' columns in the header"
            )
        return [
            Target(row.get(fields["host"]), row.get(fields["port"])) for row in reader
        ]


# Валідація
def validate_host(host: object) -> str | None:
    """Повертає текст помилки або None, якщо хост — коректні IPv4/доменне ім'я."""
    if not isinstance(host, str) or not host:
        return "Host is missing"
    if DOTTED_NUMERIC_RE.fullmatch(host):
        return None if IPV4_RE.fullmatch(host) else "Invalid IPv4 address"
    if len(host) > MAX_HOSTNAME_LEN or not DOMAIN_RE.fullmatch(host):
        return "Invalid host name"
    return None


def parse_port(raw: object) -> int:
    """Перетворює значення на номер порту 1-65535; інакше ValueError."""
    if raw is None or raw == "":
        raise ValueError("Port is missing")
    if isinstance(raw, int) and not isinstance(raw, bool):
        port = raw
    elif isinstance(raw, str) and PORT_RE.fullmatch(raw.strip()):
        port = int(raw.strip())
    else:
        raise ValueError("Port must be an integer")
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(f"Port {port} out of range ({MIN_PORT}-{MAX_PORT})")
    return port


def validate_target(target: Target) -> str | None:
    """Повертає опис усіх проблем цілі або None, якщо ціль коректна."""
    problems = []
    host_problem = validate_host(target.host)
    if host_problem:
        problems.append(host_problem)
    try:
        parse_port(target.port)
    except ValueError as exc:
        problems.append(str(exc))
    return "; ".join(problems) or None


def _printable(value: object) -> str:
    """Замінює керівні символи, щоб дані з файлу не ламали вивід і журнал."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(value))


# Перевірка з'єднання
def scan_target(target: Target, timeout: float) -> ScanResult:
    """Перевіряє одну ціль; усі мережеві помилки перетворюються на результат."""
    problem = validate_target(target)
    if problem:
        raw_port = target.port
        is_int = isinstance(raw_port, int) and not isinstance(raw_port, bool)
        return ScanResult(
            host=_printable("<missing>" if target.host is None else target.host),
            port=raw_port if is_int else _printable(raw_port or ""),
            service="N/A",
            status=Status.INVALID,
            notes=problem,
        )

    host = str(target.host)
    port = parse_port(target.port)
    service = SERVICE_NAMES.get(port, "Unknown")

    def offline(note: str, timed_out: bool = False) -> ScanResult:
        return ScanResult(
            host, port, service, Status.OFFLINE, timed_out=timed_out, notes=note
        )

    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = (time.perf_counter() - started) * 1000
    except TimeoutError:
        return offline("Connection timed out", timed_out=True)
    except ConnectionRefusedError:
        return offline("Connection refused")
    except socket.gaierror as exc:
        return offline(f"DNS resolution failed: {exc.strerror or exc}")
    except OSError as exc:
        return offline(f"Network error: {exc.strerror or exc}")
    return ScanResult(
        host,
        port,
        service,
        Status.ONLINE,
        response_time_ms=round(elapsed_ms, 1),
        notes="OK",
    )


# Статистика та вивід
def compute_stats(results: Iterable[ScanResult]) -> ScanStats:
    counts = Counter(result.status for result in results)
    online = counts[Status.ONLINE]
    offline = counts[Status.OFFLINE]
    invalid = counts[Status.INVALID]
    return ScanStats(
        total=online + offline + invalid,
        scanned=online + offline,
        online=online,
        offline=offline,
        invalid=invalid,
    )


def _shorten(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 3] + "..."


def format_table(results: list[ScanResult]) -> str:
    header = ("Target Host", "Port", "Service", "Status", "Response Time", "Notes")
    rows = [
        (
            _shorten(result.host, 32),
            str(result.port),
            result.service,
            result.status.value,
            result.response_display,
            result.notes,
        )
        for result in results
    ]
    widths = [
        max([len(h)] + [len(row[i]) for row in rows]) for i, h in enumerate(header[:-1])
    ]

    def line(cells: tuple[str, ...]) -> str:
        padded = [cell.ljust(width) for cell, width in zip(cells, widths)]
        return "  ".join([*padded, cells[-1]]).rstrip()

    lines = [line(header)]
    lines.append("-" * max(len(text) for text in [lines[0], *map(line, rows)]))
    lines.extend(line(row) for row in rows)
    return "\n".join(lines)


def print_stats(stats: ScanStats) -> None:
    print("\n=== Scan Statistics ===")
    print(f"Total Targets : {stats.total}")
    print(f"Scanned       : {stats.scanned}")
    print(f"Online        : {stats.online} ({stats.percent(stats.online):.1f}%)")
    print(f"Offline       : {stats.offline} ({stats.percent(stats.offline):.1f}%)")
    print(f"Invalid       : {stats.invalid} (skipped, not scanned)")


def _csv_safe(value: object) -> str:
    """Захист від CSV/formula injection при відкритті файлу в Excel."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def write_csv(results: Iterable[ScanResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(CSV_COLUMNS)
        for result in results:
            writer.writerow(
                [
                    _csv_safe(result.host),
                    result.port,
                    result.service,
                    result.status.value,
                    "" if result.response_time_ms is None else result.response_time_ms,
                    _csv_safe(result.notes),
                ]
            )


# Логування
def setup_logging(verbose: bool, log_file: Path | None = None) -> None:
    """Консоль: INFO (або DEBUG з --verbose). Файл аудиту: завжди DEBUG."""
    base = logging.getLogger("lab02")
    base.handlers.clear()
    base.setLevel(logging.DEBUG)
    base.propagate = False

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    base.addHandler(console)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        base.addHandler(file_handler)


# CLI
def _timeout_type(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {value!r}") from None
    if not 0 < timeout <= MAX_TIMEOUT_SEC:
        raise argparse.ArgumentTypeError(f"must be in (0, {MAX_TIMEOUT_SEC:g}] seconds")
    return timeout


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--targets", type=Path, required=True, help="шлях до JSON/CSV зі списком цілей"
    )
    parser.add_argument(
        "--timeout",
        type=_timeout_type,
        default=DEFAULT_TIMEOUT_SEC,
        help=f"таймаут з'єднання, с (типово {DEFAULT_TIMEOUT_SEC:g})",
    )
    parser.add_argument(
        "--out-csv", type=Path, help="файл CSV для збереження результату"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="докладний вивід (рівень DEBUG)"
    )
    parser.add_argument("--log-file", type=Path, help="файл аудиторського журналу")


def run(args: argparse.Namespace) -> int:
    """Виконує сканування; повертає код завершення процесу."""
    try:
        setup_logging(args.verbose, args.log_file)
    except OSError as exc:
        print(f"[ERROR] Cannot open log file: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_ERROR

    logger.info(
        "Starting service availability scan from target list %s...", args.targets
    )
    try:
        targets = load_targets(args.targets)
    except (OSError, ValueError) as exc:
        logger.error("Cannot read targets file %s: %s", args.targets, exc)
        return EXIT_INPUT_ERROR
    if not targets:
        logger.error("Targets file %s contains no records", args.targets)
        return EXIT_INPUT_ERROR
    logger.info("Loaded %d target(s), timeout = %.1f s", len(targets), args.timeout)

    results = []
    for target in targets:
        result = scan_target(target, args.timeout)
        results.append(result)
        if result.status is Status.INVALID:
            logger.warning(
                "Skipping invalid target %s:%s - %s",
                _shorten(result.host, 64),
                result.port,
                result.notes,
            )
        else:
            logger.debug(
                "%s:%s (%s) -> %s %s %s",
                result.host,
                result.port,
                result.service,
                result.status.value,
                result.response_display,
                result.notes,
            )

    print()
    print(format_table(results))
    stats = compute_stats(results)
    print_stats(stats)

    if stats.offline:
        logger.warning("%d service(s) are unreachable", stats.offline)
    if args.out_csv is not None:
        try:
            write_csv(results, args.out_csv)
        except OSError as exc:
            logger.error("Cannot write CSV report %s: %s", args.out_csv, exc)
            return EXIT_OUTPUT_ERROR
        logger.info("Detailed scan report saved to %s", args.out_csv)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Запуск окремо: python -m labs.lab02.task2 --targets ..."""
    parser = argparse.ArgumentParser(description="Сканер доступності сервісів")
    add_arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
