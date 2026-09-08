"""
alert_classifier.py

Modulo responsavel por:
    1) Detectar padroes de Brute Force, Port Scanning e Suspicious Login
       a partir dos eventos estruturados produzidos pelo log_analyzer;
    2) Classificar cada deteccao em um nivel de severidade
       (LOW / MEDIUM / HIGH / CRITICAL), sempre com justificativa;
    3) Gerar recomendacoes de investigacao (defensivas, nunca ofensivas).

Principios anti-alucinacao aplicados neste modulo:
    - Nenhum evento, IP ou usuario e inventado: tudo vem exclusivamente
      dos eventos recebidos como entrada.
    - Quando os dados sao insuficientes para uma conclusao mais forte,
      isso e informado explicitamente (severidade LOW + justificativa).
    - A linguagem usada distingue evidencia de hipotese: expressoes como
      "possivel", "indicio de" e "compativel com" sao usadas quando o
      cenario nao pode ser confirmado com certeza.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import timedelta
from typing import Optional

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_RULES_PATH = os.path.join(_BASE_DIR, "data", "detection_rules.json")
_DEFAULT_BASELINE_PATH = os.path.join(_BASE_DIR, "data", "security_alerts.json")


def load_detection_rules(path: str = _DEFAULT_RULES_PATH) -> dict:
    """Carrega as regras de deteccao (limiares configuraveis) a partir de JSON."""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_user_baseline(path: str = _DEFAULT_BASELINE_PATH) -> dict:
    """Carrega a linha de base ficticia de comportamento de login por usuario."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data.get("known_user_baseline", {})


# --------------------------------------------------------------------------- #
# Deteccao: Brute Force
# --------------------------------------------------------------------------- #

def detect_brute_force(events: list[dict], rules: dict) -> list[dict]:
    """
    Detecta multiplas tentativas de autenticacao falhas para o mesmo par
    (usuario, IP de origem) dentro de uma janela de tempo curta.

    Retorna uma lista de alertas brutos (ainda sem severidade/MITRE).
    """
    config = rules["brute_force"]
    min_attempts = config["min_failed_attempts"]
    window = timedelta(minutes=config["time_window_minutes"])

    failed_by_pair: dict[tuple, list[dict]] = defaultdict(list)
    success_by_pair: dict[tuple, list[dict]] = defaultdict(list)

    for event in events:
        if event["service"] != "sshd":
            continue
        key = (event["user"], event["source_ip"])
        if event["event_type"] == "auth_failed":
            failed_by_pair[key].append(event)
        elif event["event_type"] == "auth_success":
            success_by_pair[key].append(event)

    alerts = []
    for (user, ip), failed_events in failed_by_pair.items():
        failed_events.sort(key=lambda event: event["timestamp"])

        # Janela deslizante: para cada evento inicial, conta quantos
        # eventos subsequentes caem dentro da janela de tempo definida.
        best_window_events: list[dict] = []
        for start_index, start_event in enumerate(failed_events):
            window_end = start_event["timestamp"] + window
            window_events = [
                event for event in failed_events[start_index:]
                if event["timestamp"] <= window_end
            ]
            if len(window_events) > len(best_window_events):
                best_window_events = window_events

        if len(best_window_events) >= min_attempts:
            # Verifica se houve login bem-sucedido para o mesmo par logo apos
            # a rajada de falhas, o que eleva a gravidade (indicio de que a
            # tentativa de forca bruta pode ter tido sucesso).
            burst_end = best_window_events[-1]["timestamp"]
            had_success_after = any(
                success["timestamp"] >= burst_end
                and success["timestamp"] <= burst_end + timedelta(minutes=10)
                for success in success_by_pair.get((user, ip), [])
            )

            alerts.append({
                "detection_type": "brute_force",
                "source_ip": ip,
                "affected_user": user,
                "attempt_count": len(best_window_events),
                "window_minutes": config["time_window_minutes"],
                "had_success_after": had_success_after,
                "first_timestamp": best_window_events[0]["timestamp"],
                "last_timestamp": best_window_events[-1]["timestamp"],
                "evidence": (
                    f"{len(best_window_events)} tentativas de autenticacao falhas "
                    f"para o usuario '{user}' a partir do IP {ip}, entre "
                    f"{best_window_events[0]['timestamp'].strftime('%H:%M:%S')} e "
                    f"{best_window_events[-1]['timestamp'].strftime('%H:%M:%S')}."
                ),
            })

    return alerts


# --------------------------------------------------------------------------- #
# Deteccao: Port Scanning
# --------------------------------------------------------------------------- #

def detect_port_scanning(events: list[dict], rules: dict) -> list[dict]:
    """
    Detecta um mesmo IP de origem tentando se conectar a multiplas portas
    de destino distintas dentro de uma janela de tempo curta.
    """
    config = rules["port_scanning"]
    min_ports = config["min_distinct_ports"]
    window = timedelta(minutes=config["time_window_minutes"])

    events_by_ip: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        if event["service"] == "firewall" and event["event_type"] == "connection_attempt":
            events_by_ip[event["source_ip"]].append(event)

    alerts = []
    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda event: event["timestamp"])

        best_window_events: list[dict] = []
        for start_index, start_event in enumerate(ip_events):
            window_end = start_event["timestamp"] + window
            window_events = [
                event for event in ip_events[start_index:]
                if event["timestamp"] <= window_end
            ]
            distinct_ports = {event["port"] for event in window_events}
            if len(distinct_ports) > len({e["port"] for e in best_window_events}):
                best_window_events = window_events

        distinct_ports = sorted({event["port"] for event in best_window_events})
        if len(distinct_ports) >= min_ports:
            alerts.append({
                "detection_type": "port_scanning",
                "source_ip": ip,
                "affected_user": None,
                "distinct_ports": distinct_ports,
                "port_count": len(distinct_ports),
                "window_minutes": config["time_window_minutes"],
                "first_timestamp": best_window_events[0]["timestamp"],
                "last_timestamp": best_window_events[-1]["timestamp"],
                "evidence": (
                    f"{len(distinct_ports)} portas de destino distintas "
                    f"({', '.join(str(p) for p in distinct_ports)}) acessadas a partir "
                    f"do IP {ip}, entre "
                    f"{best_window_events[0]['timestamp'].strftime('%H:%M:%S')} e "
                    f"{best_window_events[-1]['timestamp'].strftime('%H:%M:%S')}."
                ),
            })

    return alerts


# --------------------------------------------------------------------------- #
# Deteccao: Suspicious Login
# --------------------------------------------------------------------------- #

def detect_suspicious_login(events: list[dict], rules: dict, baseline: dict) -> list[dict]:
    """
    Analisa logins bem-sucedidos em busca de padroes incomuns:
        - usuario sensivel (ex: root, admin);
        - horario fora do intervalo usual do usuario;
        - IP de origem fora da lista de IPs usuais do usuario.

    Cada motivo encontrado e listado explicitamente na evidencia, para
    que a conclusao nunca va alem do que os dados sustentam.
    """
    config = rules["suspicious_login"]
    sensitive_users = set(config["sensitive_users"])
    unusual_start = config["unusual_hour_start"]
    unusual_end = config["unusual_hour_end"]

    alerts = []
    for event in events:
        if event["service"] != "sshd" or event["event_type"] != "auth_success":
            continue

        reasons = []
        user = event["user"]
        hour = event["timestamp"].hour

        if user in sensitive_users:
            reasons.append(f"login em conta sensivel ('{user}')")

        if unusual_start <= hour < unusual_end:
            reasons.append(
                f"horario incomum ({event['timestamp'].strftime('%H:%M:%S')})"
            )

        user_baseline = baseline.get(user)
        if user_baseline is not None:
            usual_ips = user_baseline.get("usual_ips", [])
            if usual_ips and event["source_ip"] not in usual_ips:
                reasons.append(
                    f"origem ({event['source_ip']}) fora da lista de IPs usuais do usuario"
                )

        if reasons:
            alerts.append({
                "detection_type": "suspicious_login",
                "source_ip": event["source_ip"],
                "affected_user": user,
                "reasons": reasons,
                "timestamp": event["timestamp"],
                "evidence": (
                    f"Login bem-sucedido do usuario '{user}' a partir do IP "
                    f"{event['source_ip']} em {event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}. "
                    f"Motivo(s) do alerta: {'; '.join(reasons)}."
                ),
            })

    return alerts


# --------------------------------------------------------------------------- #
# Deteccao: eventos insuficientes para conclusao
# --------------------------------------------------------------------------- #

def detect_insufficient_data(events: list[dict], rules: dict, existing_alerts: list[dict]) -> list[dict]:
    """
    Identifica pares (usuario, IP) com tentativas de autenticacao falhas
    que NAO atingiram o limiar de Brute Force, para deixar explicito que
    ha atividade registrada, mas sem evidencias suficientes para uma
    conclusao mais forte. Evita o silencio sobre eventos que o analista
    poderia querer revisar manualmente.
    """
    threshold = rules["insufficient_data"]["min_events_for_conclusion"]

    flagged_pairs = {
        (alert["affected_user"], alert["source_ip"])
        for alert in existing_alerts
        if alert["detection_type"] == "brute_force"
    }

    failed_by_pair: dict[tuple, list[dict]] = defaultdict(list)
    for event in events:
        if event["service"] == "sshd" and event["event_type"] == "auth_failed":
            key = (event["user"], event["source_ip"])
            failed_by_pair[key].append(event)

    alerts = []
    for (user, ip), failed_events in failed_by_pair.items():
        if (user, ip) in flagged_pairs:
            continue  # ja coberto por um alerta de Brute Force
        if 0 < len(failed_events) < threshold:
            failed_events.sort(key=lambda event: event["timestamp"])
            alerts.append({
                "detection_type": "insufficient_data",
                "source_ip": ip,
                "affected_user": user,
                "attempt_count": len(failed_events),
                "first_timestamp": failed_events[0]["timestamp"],
                "last_timestamp": failed_events[-1]["timestamp"],
                "evidence": (
                    f"{len(failed_events)} tentativa(s) de autenticacao falha(s) "
                    f"para o usuario '{user}' a partir do IP {ip}. Volume abaixo do "
                    f"limiar minimo ({threshold}) definido para uma conclusao mais forte."
                ),
            })

    return alerts


# --------------------------------------------------------------------------- #
# Classificacao de severidade
# --------------------------------------------------------------------------- #

def classify_severity(alert: dict, rules: dict) -> tuple[str, str]:
    """
    Aplica regras claras de severidade para cada tipo de deteccao e
    retorna uma tupla (severidade, justificativa).
    """
    detection_type = alert["detection_type"]

    if detection_type == "brute_force":
        threshold = rules["brute_force"]["min_failed_attempts"]
        if alert.get("had_success_after"):
            return (
                "CRITICAL",
                "Padrao de forca bruta seguido por um login bem-sucedido para o "
                "mesmo usuario/origem: indicio de possivel comprometimento da conta.",
            )
        if alert["attempt_count"] >= threshold * 2:
            return (
                "HIGH",
                f"Volume de tentativas ({alert['attempt_count']}) e muito superior "
                f"ao limiar minimo ({threshold}), fortemente compativel com atividade "
                "de forca bruta automatizada.",
            )
        return (
            "HIGH",
            f"Numero de tentativas falhas ({alert['attempt_count']}) atingiu ou "
            f"superou o limiar definido ({threshold}) para o mesmo usuario e origem "
            "na janela de tempo analisada.",
        )

    if detection_type == "port_scanning":
        threshold = rules["port_scanning"]["min_distinct_ports"]
        if alert["port_count"] >= threshold * 2:
            return (
                "HIGH",
                f"Numero de portas distintas acessadas ({alert['port_count']}) e "
                f"muito superior ao limiar minimo ({threshold}), compativel com "
                "varredura automatizada de servicos.",
            )
        return (
            "MEDIUM",
            f"Numero de portas distintas acessadas ({alert['port_count']}) atingiu "
            f"o limiar minimo ({threshold}) para uma possivel varredura, mas sem "
            "evidencia de exploracao ou acesso obtido.",
        )

    if detection_type == "suspicious_login":
        if len(alert["reasons"]) >= 3:
            return (
                "HIGH",
                "Multiplos indicadores de anomalia presentes simultaneamente "
                f"({'; '.join(alert['reasons'])}), o que aumenta a probabilidade "
                "de comportamento malicioso.",
            )
        return (
            "MEDIUM",
            f"Indicio de comportamento incomum de login ({'; '.join(alert['reasons'])}), "
            "que merece investigacao, mas sem confirmacao de atividade maliciosa.",
        )

    if detection_type == "insufficient_data":
        return (
            "LOW",
            "Volume de eventos relacionados e baixo demais para caracterizar "
            "comportamento claramente suspeito; recomenda-se apenas monitoramento.",
        )

    return ("LOW", "Tipo de deteccao sem regra de severidade especifica definida.")


# --------------------------------------------------------------------------- #
# Recomendacoes de investigacao (sempre defensivas)
# --------------------------------------------------------------------------- #

_RECOMMENDATIONS = {
    "brute_force": [
        "Verificar se houve autenticacao bem-sucedida apos as tentativas falhas.",
        "Investigar a reputacao e o historico do IP de origem.",
        "Verificar se outros usuarios foram alvo do mesmo IP de origem.",
        "Avaliar bloqueio temporario ou rate limiting para a origem, caso confirmado.",
        "Revisar politica de bloqueio de conta apos multiplas falhas (account lockout).",
    ],
    "port_scanning": [
        "Verificar se alguma das portas escaneadas expõe um servico vulneravel.",
        "Investigar a reputacao do IP de origem.",
        "Confirmar se as regras de firewall bloquearam corretamente as tentativas.",
        "Monitorar o IP de origem para novas atividades nos proximos periodos.",
    ],
    "suspicious_login": [
        "Confirmar com o usuario legitimo se o acesso foi realizado por ele.",
        "Verificar o historico recente de acessos da conta afetada.",
        "Avaliar a origem geografica/rede do IP utilizado no login.",
        "Considerar exigir autenticacao multifator (MFA) para a conta, se ainda nao houver.",
    ],
    "insufficient_data": [
        "Manter o IP e o usuario em observacao para eventos futuros.",
        "Nao classificar como incidente confirmado sem evidencias adicionais.",
        "Revisar novamente caso novas tentativas ocorram dentro de uma janela maior.",
    ],
}


def generate_recommendations(detection_type: str) -> list[str]:
    """Retorna a lista de recomendacoes defensivas para um tipo de deteccao."""
    return list(_RECOMMENDATIONS.get(detection_type, [
        "Revisar manualmente o evento para determinar os proximos passos."
    ]))


# --------------------------------------------------------------------------- #
# Orquestracao
# --------------------------------------------------------------------------- #

def run_all_detections(
    events: list[dict],
    rules: Optional[dict] = None,
    baseline: Optional[dict] = None,
) -> list[dict]:
    """
    Executa todas as deteccoes disponiveis sobre a lista de eventos e
    retorna alertas completos: tipo, severidade, justificativa, evidencia
    e recomendacoes. A associacao com o MITRE ATT&CK e feita pelo modulo
    'mitre.py' na camada de geracao de relatorio, para manter este modulo
    focado apenas em deteccao e classificacao.
    """
    if rules is None:
        rules = load_detection_rules()
    if baseline is None:
        baseline = load_user_baseline()

    alerts = []
    alerts += detect_brute_force(events, rules)
    alerts += detect_port_scanning(events, rules)
    alerts += detect_suspicious_login(events, rules, baseline)
    alerts += detect_insufficient_data(events, rules, alerts)

    for alert in alerts:
        severity, justification = classify_severity(alert, rules)
        alert["severity"] = severity
        alert["justification"] = justification
        alert["recommendations"] = generate_recommendations(alert["detection_type"])

    return alerts
