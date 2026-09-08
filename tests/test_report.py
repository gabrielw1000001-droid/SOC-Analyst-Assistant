import json
import os
from datetime import datetime

import incident_report


def _sample_alert():
    return {
        "detection_type": "brute_force",
        "source_ip": "192.168.1.50",
        "affected_user": "admin",
        "attempt_count": 12,
        "had_success_after": False,
        "first_timestamp": datetime(2026, 9, 7, 22, 15, 1),
        "last_timestamp": datetime(2026, 9, 7, 22, 17, 19),
        "evidence": "12 tentativas de autenticacao falhas para o usuario 'admin'.",
        "severity": "HIGH",
        "justification": "Numero de tentativas falhas atingiu o limiar definido.",
        "recommendations": ["Investigar o IP de origem.", "Verificar autenticacao bem-sucedida."],
    }


def test_build_report_contains_required_fields():
    report = incident_report.build_report(_sample_alert(), incident_number=1)

    required_fields = {
        "incident_id", "date", "event_type", "severity", "source_ip",
        "affected_user", "evidence", "detection_rule", "mitre_attack",
        "recommendations", "status",
    }
    assert required_fields.issubset(report.keys())
    assert report["incident_id"] == "INC-001"
    assert report["event_type"] == "Brute Force"
    assert report["status"] == "UNDER INVESTIGATION"


def test_build_report_associates_correct_mitre_technique():
    report = incident_report.build_report(_sample_alert(), incident_number=1)
    assert any("T1110" in technique for technique in report["mitre_attack"])


def test_format_report_text_includes_key_sections():
    report = incident_report.build_report(_sample_alert(), incident_number=1)
    text = incident_report.format_report_text(report)

    assert "SECURITY INCIDENT REPORT" in text
    assert "INC-001" in text
    assert "Brute Force" not in text or "Type: Brute Force" in text
    assert "Recommendations:" in text
    assert "MITRE ATT&CK:" in text


def test_save_report_json_writes_valid_json_file(tmp_path):
    report = incident_report.build_report(_sample_alert(), incident_number=1)
    output_dir = str(tmp_path / "reports")

    saved_path = incident_report.save_report_json(report, output_dir=output_dir)

    assert os.path.isfile(saved_path)
    with open(saved_path, "r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    assert loaded["incident_id"] == "INC-001"


def test_build_reports_from_alerts_numbers_sequentially():
    alerts = [_sample_alert(), _sample_alert()]
    reports = incident_report.build_reports_from_alerts(alerts)

    assert [report["incident_id"] for report in reports] == ["INC-001", "INC-002"]
