"""
incident_report.py

Modulo responsavel por transformar um alerta ja classificado (produzido
por alert_classifier.py) em um relatorio de incidente estruturado,
pronto para ser exibido na interface, impresso em texto ou salvo em
formato JSON.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional

from mitre import get_techniques_for_detection, load_mitre_database

_DETECTION_TYPE_LABELS = {
    "brute_force": "Brute Force",
    "port_scanning": "Port Scanning",
    "suspicious_login": "Suspicious Login",
    "insufficient_data": "Insufficient Data",
}

_DETECTION_RULE_LABELS = {
    "brute_force": "Multiplas tentativas de autenticacao falhas para o mesmo "
                   "usuario/origem dentro de uma janela de tempo curta.",
    "port_scanning": "Multiplas portas de destino distintas acessadas pela "
                      "mesma origem dentro de uma janela de tempo curta.",
    "suspicious_login": "Login bem-sucedido com um ou mais indicadores de "
                         "anomalia (usuario sensivel, horario incomum ou origem incomum).",
    "insufficient_data": "Eventos relacionados presentes, porem abaixo do "
                          "limiar minimo para uma conclusao mais forte.",
}


def build_report(alert: dict, incident_number: int, mitre_database: Optional[dict] = None) -> dict:
    """
    Monta um relatorio de incidente estruturado a partir de um alerta
    ja classificado (com severidade, justificativa e recomendacoes).
    """
    if mitre_database is None:
        mitre_database = load_mitre_database()

    techniques = get_techniques_for_detection(alert["detection_type"], mitre_database)
    mitre_list = [f"{tech['id']} - {tech['name']}" for tech in techniques]

    reference_timestamp = alert.get("last_timestamp") or alert.get("timestamp")
    report_date = (
        reference_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(reference_timestamp, datetime)
        else "N/A"
    )

    return {
        "incident_id": f"INC-{incident_number:03d}",
        "date": report_date,
        "event_type": _DETECTION_TYPE_LABELS.get(alert["detection_type"], alert["detection_type"]),
        "severity": alert["severity"],
        "severity_justification": alert["justification"],
        "source_ip": alert.get("source_ip") or "N/A",
        "affected_user": alert.get("affected_user") or "N/A",
        "evidence": alert["evidence"],
        "detection_rule": _DETECTION_RULE_LABELS.get(alert["detection_type"], "N/A"),
        "mitre_attack": mitre_list if mitre_list else ["N/A - Nenhuma tecnica associada"],
        "recommendations": alert["recommendations"],
        "status": "UNDER INVESTIGATION",
    }


def build_reports_from_alerts(alerts: list[dict]) -> list[dict]:
    """Constroi um relatorio para cada alerta de uma lista, numerando-os em sequencia."""
    mitre_database = load_mitre_database()
    return [
        build_report(alert, index + 1, mitre_database)
        for index, alert in enumerate(alerts)
    ]


def format_report_text(report: dict) -> str:
    """Formata um relatorio de incidente como texto legivel, no estilo de um laudo."""
    lines = [
        "=" * 60,
        "SECURITY INCIDENT REPORT",
        "=" * 60,
        "",
        f"Incident ID: {report['incident_id']}",
        f"Date: {report['date']}",
        "",
        f"Type: {report['event_type']}",
        "",
        f"Severity: {report['severity']}",
        f"Justification: {report['severity_justification']}",
        "",
        f"Source IP: {report['source_ip']}",
        f"Affected User: {report['affected_user']}",
        "",
        "Evidence:",
        f"  {report['evidence']}",
        "",
        f"Detection Rule: {report['detection_rule']}",
        "",
        "MITRE ATT&CK:",
    ]
    lines += [f"  {technique}" for technique in report["mitre_attack"]]
    lines += ["", "Recommendations:"]
    lines += [f"  - {item}" for item in report["recommendations"]]
    lines += ["", f"Status: {report['status']}", "=" * 60]

    return "\n".join(lines)


def save_report_json(report: dict, output_dir: str = "reports") -> str:
    """
    Salva um relatorio individual em formato JSON dentro do diretorio de
    saida informado (criado automaticamente se nao existir).

    Retorna o caminho completo do arquivo salvo.
    """
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, f"{report['incident_id']}.json")
    with open(file_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=4)
    return file_path
