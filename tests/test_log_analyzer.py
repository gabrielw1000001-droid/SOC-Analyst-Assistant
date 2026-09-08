import os
from datetime import datetime

import log_analyzer


def test_parse_log_line_ignores_comments_and_blank_lines():
    assert log_analyzer.parse_log_line("# comentario") is None
    assert log_analyzer.parse_log_line("   ") is None
    assert log_analyzer.parse_log_line("") is None


def test_parse_log_line_extracts_failed_login_fields():
    line = "Sep 07 22:15:01 server sshd[1024]: Failed password for admin from 192.168.1.50 port 45201 ssh2"
    event = log_analyzer.parse_log_line(line)

    assert event is not None
    assert event["event_type"] == "auth_failed"
    assert event["user"] == "admin"
    assert event["source_ip"] == "192.168.1.50"
    assert event["port"] == 45201
    assert event["service"] == "sshd"
    assert isinstance(event["timestamp"], datetime)


def test_parse_log_line_extracts_successful_login():
    line = "Sep 07 09:02:11 server sshd[2048]: Accepted password for jsilva from 10.0.0.15 port 51122 ssh2"
    event = log_analyzer.parse_log_line(line)

    assert event is not None
    assert event["event_type"] == "auth_success"
    assert event["user"] == "jsilva"
    assert event["source_ip"] == "10.0.0.15"


def test_parse_log_line_extracts_firewall_connection_attempt():
    line = "Sep 07 23:05:01 server firewall[4001]: Connection attempt from 203.0.113.77 to port 21 blocked"
    event = log_analyzer.parse_log_line(line)

    assert event is not None
    assert event["service"] == "firewall"
    assert event["event_type"] == "connection_attempt"
    assert event["source_ip"] == "203.0.113.77"
    assert event["port"] == 21


def test_parse_log_line_returns_none_for_unrecognized_format():
    line = "this is not a recognizable log line"
    assert log_analyzer.parse_log_line(line) is None


def test_parse_log_file_returns_sorted_events(tmp_path):
    log_content = (
        "Sep 07 09:00:00 server sshd[1]: Accepted password for user1 from 10.0.0.1 port 1000 ssh2\n"
        "Sep 07 08:00:00 server sshd[2]: Accepted password for user2 from 10.0.0.2 port 1001 ssh2\n"
        "# comentario no meio do arquivo\n"
        "linha invalida sem padrao reconhecido\n"
    )
    log_file = tmp_path / "sample.log"
    log_file.write_text(log_content, encoding="utf-8")

    events = log_analyzer.parse_log_file(str(log_file))

    assert len(events) == 2
    # Deve estar ordenado cronologicamente: 08:00 antes de 09:00
    assert events[0]["user"] == "user2"
    assert events[1]["user"] == "user1"


def test_parse_log_file_on_bundled_sample_log():
    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sample_auth.log"
    )
    events = log_analyzer.parse_log_file(sample_path)
    assert len(events) > 0
