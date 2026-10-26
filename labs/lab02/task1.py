"""Завдання 1: модель користувача, безпечних сесій та журналу аудиту.

Демонстрація запускається командою ``python -m labs.lab02.main demo``
і не виконується під час імпорту цього модуля.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import ClassVar

# Константи
PBKDF2_HASH_NAME = "sha256"
PBKDF2_ITERATIONS = 600_000  # рекомендація OWASP для PBKDF2-HMAC-SHA256
SALT_SIZE_BYTES = 16
MIN_PASSWORD_LENGTH = 8
SESSION_TIMEOUT_SEC = 900

# Локальна частина: латинська літера + ще 2-63 символи (літери, цифри, "_"),
# разом 3-64 символи; домен містить принаймні одну крапку.
# fullmatch (а не match + "$") не пропускає зайвий символ нового рядка в кінці.
EMAIL_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9_]{2,63}@(?:[A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z]{2,}"
)

ALLOWED_AUDIT_ACTIONS = frozenset({"login_success", "login_failure", "logout"})


def utc_now() -> datetime:
    """Поточний час UTC з часовим поясом (без неоднозначності локального часу)."""
    return datetime.now(timezone.utc)


def validate_ip(ip: str) -> str:
    """Перевіряє IPv4/IPv6-адресу: TypeError для не-рядка, ValueError для формату."""
    if not isinstance(ip, str):
        raise TypeError("IP address must be a string")
    ipaddress.ip_address(ip)  # ValueError, якщо формат некоректний
    return ip


# User
class User:
    """Користувач із безпечним зберіганням пароля (PBKDF2 + випадкова сіль)."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        password: str | None = None,
        active: bool = True,
    ) -> None:
        if not isinstance(username, str) or not username.strip():
            raise ValueError("username must be a non-empty string")
        self.username = username
        self.email = email  # проходить через setter із перевіркою
        self.role = role
        self.active = active
        # Подвійне підкреслення -> name mangling: _User__password_hash
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None
        if password is not None:
            self.set_password(password)

    # email як property
    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or EMAIL_RE.fullmatch(value) is None:
            raise ValueError(f"Invalid email format: {value!r}")
        self._email = value

    # робота з паролем
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            PBKDF2_HASH_NAME,
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
        )

    def set_password(self, password: str) -> None:
        """Генерує нову сіль і зберігає лише хеш (пароль не зберігається)."""
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(
                f"Password must be a string of at least {MIN_PASSWORD_LENGTH} chars"
            )
        salt = os.urandom(SALT_SIZE_BYTES)
        self.__password_salt = salt
        self.__password_hash = self._derive_key(password, salt)

    def check_password(self, password: str) -> bool:
        """Порівнює хеш у сталий час (hmac.compare_digest)."""
        if (
            not isinstance(password, str)
            or self.__password_hash is None
            or self.__password_salt is None
        ):
            return False
        candidate = self._derive_key(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        state = "active" if self.active else "deactivated"
        return f"User {self.username} <{self.email}> role={self.role} ({state})"

    def __repr__(self) -> str:
        # Хеш і сіль навмисно не потрапляють у repr.
        return f"{type(self).__name__}(username={self.username!r})"


# Admin (наслідування)
class Admin(User):
    """Адміністратор = користувач (Is-A) + набір дозволів."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str | None = None,
        permissions: Iterable[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(
            username, email, role="admin", password=password, active=active
        )
        # Нова колекція для кожного об'єкта (не змінюваний типовий аргумент).
        self.permissions: set[str] = set()
        for permission in permissions or ():
            self.grant_permission(permission)

    @staticmethod
    def _check_permission_name(permission: str) -> str:
        if not isinstance(permission, str) or not permission.strip():
            raise ValueError("permission must be a non-empty string")
        return permission.strip()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(self._check_permission_name(permission))

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(self._check_permission_name(permission))

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        rights = ", ".join(sorted(self.permissions)) or "none"
        return f"{super().__str__()} permissions=[{rights}]"


# Session
@dataclass
class Session:
    """Сеанс користувача; усі часові мітки — UTC із часовим поясом."""

    ip: str
    login_time: datetime = field(default_factory=utc_now)
    last_activity: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        validate_ip(self.ip)
        if self.login_time.tzinfo is None or self.last_activity.tzinfo is None:
            raise ValueError("Session timestamps must be timezone-aware (UTC)")

    def touch(self) -> None:
        self.last_activity = utc_now()

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec must be positive")
        idle = utc_now() - self.last_activity
        return idle < timedelta(seconds=timeout_sec)


# AuditLog
@dataclass(frozen=True)
class AuditEntry:
    """Незмінний запис журналу: @dataclass дає __init__, __repr__, __eq__."""

    timestamp: datetime
    username: str
    action: str

    def __str__(self) -> str:
        stamp = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return f"{stamp} UTC | {self.username:<12} | {self.action}"


class AuditLog:
    """Журнал подій автентифікації (паролі в журнал не потрапляють)."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def add_log(self, username: str, action: str) -> AuditEntry:
        if action not in ALLOWED_AUDIT_ACTIONS:
            raise ValueError(f"Unknown audit action: {action!r}")
        # Захист від log injection: прибираємо керівні символи й обмежуємо довжину.
        safe_name = re.sub(r"[^\w.@-]", "?", str(username))[:64] or "unknown"
        entry = AuditEntry(utc_now(), safe_name, action)
        self._entries.append(entry)
        return entry

    def show_all(self) -> None:
        if not self._entries:
            print("(audit log is empty)")
            return
        for number, entry in enumerate(self._entries, start=1):
            print(f"{number:>2}. {entry}")


# UserAccount (композиція + спеціальні методи)
class UserAccount:
    """Обліковий запис: ВМІЩУЄ (Has-A) User, Session та AuditLog."""

    # Ключ -> допустимі типи значення. Хеш і сіль серед ключів відсутні.
    _FIELD_TYPES: ClassVar[dict[str, tuple[type, ...]]] = {
        "user": (User,),
        "session": (Session, type(None)),
        "audit_log": (AuditLog,),
    }

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        if not isinstance(user, User):
            raise TypeError("user must be a User instance")
        self._user = user
        self._session = session
        self._audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        validate_ip(ip)
        success = (
            username == self._user.username
            and self._user.active
            and self._user.check_password(password)
        )
        if not success:
            self._audit_log.add_log(username, "login_failure")
            return False
        self._session = Session(ip)  # сеанс створюється лише після успіху
        self._session.touch()
        self._audit_log.add_log(self._user.username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        """Успішна перевірка подовжує сеанс, невдала — ні."""
        if (
            self._session is None
            or not self._user.active
            or not self._session.is_active(SESSION_TIMEOUT_SEC)
        ):
            return False
        self._session.touch()
        return True

    def logout(self) -> bool:
        if self._session is None:
            return False
        self._audit_log.add_log(self._user.username, "logout")
        self._session = None
        return True

    def __getitem__(self, key: str) -> object:
        if key not in self._FIELD_TYPES:
            raise KeyError(key)
        return getattr(self, f"_{key}")

    def __setitem__(self, key: str, value: object) -> None:
        if key not in self._FIELD_TYPES:
            raise KeyError(key)
        if not isinstance(value, self._FIELD_TYPES[key]):
            raise TypeError(f"Wrong value type for {key!r}: {type(value).__name__}")
        setattr(self, f"_{key}", value)
        if key == "user":
            self._session = None  # новий користувач не успадковує чужий сеанс

    def __str__(self) -> str:
        status = "authenticated" if self.is_authenticated() else "anonymous"
        return f"UserAccount({self._user.username}, {status})"


# Демонстрація
DEMO_PASSWORD = "Str0ng_Demo#Pass"


def _title(text: str) -> None:
    print(f"\n--- {text} ---")


def run_demo() -> None:
    """Сценарій демонстрації; викликається з main.py (команда demo)."""
    print("=== Завдання 1: користувачі, сеанси, аудит ===")

    admin = Admin(
        "alice_admin",
        "alice_admin@example.com",
        password=DEMO_PASSWORD,
        permissions={"read_logs"},
    )
    account = UserAccount(admin)
    print(admin)
    print(f"Admin є User? {isinstance(admin, User)}")

    _title("Невдалий і успішний вхід")
    ok = account.login("alice_admin", "wrong_password", "192.168.1.10")
    print(f"Невірний пароль -> {ok}; автентифікований: {account.is_authenticated()}")
    ok = account.login("alice_admin", DEMO_PASSWORD, "192.168.1.10")
    print(f"Вірний пароль   -> {ok}; автентифікований: {account.is_authenticated()}")

    _title("Зміна email із валідацією")
    user = account["user"]
    user.email = "alice_new@corp.example.org"
    print(f"Новий email: {user.email}")
    for bad_email in ("1alice@example.com", "ab@example.com", "alice@localhost"):
        try:
            user.email = bad_email
        except ValueError as exc:
            print(f"Відхилено: {exc}")

    _title("Права адміністратора")
    admin.grant_permission("manage_users")
    admin.revoke_permission("read_logs")
    print(admin)
    print(f"manage_users: {admin.has_permission('manage_users')}")
    print(f"read_logs:    {admin.has_permission('read_logs')}")

    _title("Захист ключів UserAccount")
    for bad_key in ("password_hash", "password_salt"):
        try:
            account[bad_key]
        except KeyError as exc:
            print(f"account[{bad_key!r}] -> KeyError {exc}")
    try:
        account["user"] = "not a user"
    except TypeError as exc:
        print(f"account['user'] = str -> TypeError: {exc}")

    _title("Завершення сеансу за таймаутом")
    session = account["session"]
    session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print(f"Минуло > {SESSION_TIMEOUT_SEC} c без активності")
    print(f"Автентифікований: {account.is_authenticated()}")

    _title("Повторний вхід і вихід")
    account.login("alice_admin", DEMO_PASSWORD, "192.168.1.10")
    print(f"Після входу: {account.is_authenticated()}")
    account.logout()
    print(f"Після виходу: {account.is_authenticated()}")

    _title("Деактивований користувач")
    admin.deactivate()
    ok = account.login("alice_admin", DEMO_PASSWORD, "192.168.1.10")
    print(f"Вхід деактивованого користувача -> {ok}")

    _title("Журнал аудиту (AuditLog)")
    account["audit_log"].show_all()


if __name__ == "__main__":
    run_demo()
