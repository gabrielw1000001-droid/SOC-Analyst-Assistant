"""
log_analyzer.py

Modulo responsavel por ler arquivos de log em texto puro e transformar
cada linha reconhecida em um evento estruturado (dicionario Python).

Este modulo NAO realiza nenhuma deteccao ou classificacao de ameacas.
Sua unica responsabilidade e o parsing (extracao de dados).

Formatos de log reconhecidos nesta V1:
    1) Autenticacao SSH (Failed password / Accepted password)
    2) Bloqueios de firewall (Connection attempt ... to port ... blocked)

Linhas que nao correspondam a nenhum padrao conhecido, ou que sejam
comentarios (iniciados por '#') ou em branco, sao ignoradas.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

# Ano de referencia usado para completar timestamps do syslog, que nao
# incluem o ano. Como os dados sao simulados, um ano fixo e suficiente
# para permitir ordenacao e calculo de janelas de tempo.
REFERENCE_YEAR = datetime.now().year

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# --- Padroes de autenticacao SSH -------------------------------------------------
_SSH_PATTERN = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<result>Failed|Accepted)\s+password\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)\s+(?P<proto>\S+)"
)

# --- Padrao de bloqueio de firewall (usado no cenario de Port Scanning) ---------
_FIREWALL_PATTERN = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+firewall\[(?P<pid>\d+)\]:\s+"
    r"Connection attempt from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+to\s+port\s+"
    r"(?P<port>\d+)\s+(?P<action>\w+)"
)


def _build_timestamp(month_abbr: str, day: str, time_str: str) -> Optional[datetime]:
    """Converte os campos de data/hora extraidos do log em um objeto datetime."""
    month = _MONTHS.get(month_abbr)
    if month is None:
        return None
    try:
        hour, minute, second = (int(part) for part in time_str.split(":"))
        return datetime(REFERENCE_YEAR, month, int(day), hour, minute, second)
    except ValueError:
        return None


def parse_log_line(line: str) -> Optional[dict]:
    """
    Tenta interpretar uma unica linha de log.

    Retorna um dicionario com os dados estruturados do evento, ou None
    se a linha for um comentario, estiver em branco, ou nao corresponder
    a nenhum padrao conhecido.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    match = _SSH_PATTERN.match(stripped)
    if match:
        data = match.groupdict()
        timestamp = _build_timestamp(data["month"], data["day"], data["time"])
        if timestamp is None:
            return None
        return {
            "raw_line": stripped,
            "timestamp": timestamp,
            "host": data["host"],
            "service": "sshd",
            "event_type": "auth_failed" if data["result"] == "Failed" else "auth_success",
            "user": data["user"],
            "source_ip": data["ip"],
            "port": int(data["port"]),
        }

    match = _FIREWALL_PATTERN.match(stripped)
    if match:
        data = match.groupdict()
        timestamp = _build_timestamp(data["month"], data["day"], data["time"])
        if timestamp is None:
            return None
        return {
            "raw_line": stripped,
            "timestamp": timestamp,
            "host": data["host"],
            "service": "firewall",
            "event_type": "connection_attempt",
            "user": None,
            "source_ip": data["ip"],
            "port": int(data["port"]),
            "action": data["action"],
        }

    return None


def parse_log_file(file_path: str) -> list[dict]:
    """
    Le um arquivo de log linha por linha e retorna a lista de eventos
    estruturados reconhecidos, ordenados cronologicamente.

    Linhas nao reconhecidas sao silenciosamente ignoradas (parsing
    tolerante a ruido, comum em arquivos de log reais).
    """
    events: list[dict] = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            event = parse_log_line(line)
            if event is not None:
                events.append(event)

    events.sort(key=lambda event: event["timestamp"])
    return events
