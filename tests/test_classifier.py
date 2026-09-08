from datetime import datetime, timedelta

import alert_classifier


def _make_failed_event(user, ip, timestamp, port=22000):
    return {
        "raw_line": "simulado",
        "timestamp": timestamp,
        "host": "server",
        "service": "sshd",
        "event_type": "auth_failed",
        "user": user,
        "source_ip": ip,
        "port": port,
    }


def _make_success_event(user, ip, timestamp, port=22000):
    event = _make_failed_event(user, ip, timestamp, port)
    event["event_type"] = "auth_success"
    return event


def _make_connection_event(ip, port, timestamp):
    return {
        "raw_line": "simulado",
        "timestamp": timestamp,
        "host": "server",
        "service": "firewall",
        "event_type": "connection_attempt",
        "user": None,
        "source_ip": ip,
        "port": port,
        "action": "blocked",
    }


def _rules():
    return alert_classifier.load_detection_rules()


def test_detect_brute_force_flags_burst_of_failures():
    base_time = datetime(2026, 1, 1, 10, 0, 0)
    events = [
        _make_failed_event("admin", "192.168.1.50", base_time + timedelta(seconds=i * 10))
        for i in range(6)
    ]

    alerts = alert_classifier.detect_brute_force(events, _rules())

    assert len(alerts) == 1
    assert alerts[0]["detection_type"] == "brute_force"
    assert alerts[0]["affected_user"] == "admin"
    assert alerts[0]["attempt_count"] >= 5


def test_detect_brute_force_ignores_isolated_failures():
    base_time = datetime(2026, 1, 1, 10, 0, 0)
    events = [
        _make_failed_event("mcosta", "172.16.0.40", base_time),
        _make_failed_event("mcosta", "172.16.0.40", base_time + timedelta(hours=2)),
    ]

    alerts = alert_classifier.detect_brute_force(events, _rules())

    assert alerts == []


def test_detect_port_scanning_flags_many_distinct_ports():
    base_time = datetime(2026, 1, 1, 23, 5, 0)
    ports = [21, 22, 23, 25, 80, 443, 3306]
    events = [
        _make_connection_event("203.0.113.77", port, base_time + timedelta(seconds=i * 2))
        for i, port in enumerate(ports)
    ]

    alerts = alert_classifier.detect_port_scanning(events, _rules())

    assert len(alerts) == 1
    assert alerts[0]["detection_type"] == "port_scanning"
    assert alerts[0]["port_count"] == len(ports)


def test_detect_suspicious_login_flags_unknown_ip_for_known_user():
    baseline = {"jsilva": {"usual_ips": ["10.0.0.15"], "usual_hour_start": 7, "usual_hour_end": 19}}
    events = [_make_success_event("jsilva", "198.51.100.99", datetime(2026, 1, 1, 12, 0, 0))]

    alerts = alert_classifier.detect_suspicious_login(events, _rules(), baseline)

    assert len(alerts) == 1
    assert "origem" in alerts[0]["reasons"][0] or any("origem" in reason for reason in alerts[0]["reasons"])


def test_classify_severity_brute_force_returns_high_with_justification():
    alert = {
        "detection_type": "brute_force",
        "attempt_count": 6,
        "had_success_after": False,
    }
    severity, justification = alert_classifier.classify_severity(alert, _rules())

    assert severity == "HIGH"
    assert justification  # justificativa nao deve ser vazia


def test_classify_severity_brute_force_with_success_after_is_critical():
    alert = {
        "detection_type": "brute_force",
        "attempt_count": 6,
        "had_success_after": True,
    }
    severity, _ = alert_classifier.classify_severity(alert, _rules())

    assert severity == "CRITICAL"


def test_detect_insufficient_data_flags_low_volume_events():
    base_time = datetime(2026, 1, 1, 14, 0, 0)
    events = [
        _make_failed_event("mcosta", "172.16.0.40", base_time),
        _make_failed_event("mcosta", "172.16.0.40", base_time + timedelta(hours=2)),
    ]

    alerts = alert_classifier.detect_insufficient_data(events, _rules(), existing_alerts=[])

    assert len(alerts) == 1
    assert alerts[0]["detection_type"] == "insufficient_data"


def test_run_all_detections_on_bundled_sample_log_produces_all_scenarios():
    import os

    import log_analyzer

    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sample_auth.log"
    )
    events = log_analyzer.parse_log_file(sample_path)
    alerts = alert_classifier.run_all_detections(events)

    detection_types = {alert["detection_type"] for alert in alerts}
    assert "brute_force" in detection_types
    assert "port_scanning" in detection_types
    assert "suspicious_login" in detection_types
    assert "insufficient_data" in detection_types

    for alert in alerts:
        assert alert["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert alert["justification"]
        assert alert["recommendations"]
