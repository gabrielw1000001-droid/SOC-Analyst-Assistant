"""
mitre.py

Modulo responsavel por carregar a base local de tecnicas MITRE ATT&CK
(data/mitre_attack.json) e fornecer consultas simples sobre ela.

Este modulo NAO realiza deteccao. Ele apenas expoe os metadados das
tecnicas para que o classificador possa anexa-los a um alerta ja
detectado por outras regras.
"""

from __future__ import annotations

import json
import os
from typing import Optional

_DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "mitre_attack.json"
)

# Mapeamento fixo entre o tipo de deteccao interno do projeto e a(s)
# tecnica(s) MITRE ATT&CK correspondentes. Mantido simples e explicito,
# conforme o escopo da V1.
DETECTION_TO_TECHNIQUE = {
    "brute_force": ["T1110"],
    "port_scanning": ["T1046"],
    "suspicious_login": ["T1078"],
}


def load_mitre_database(path: str = _DEFAULT_PATH) -> dict:
    """Carrega a base local de tecnicas MITRE ATT&CK a partir de um arquivo JSON."""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def get_technique(technique_id: str, database: Optional[dict] = None) -> Optional[dict]:
    """Retorna os metadados de uma tecnica pelo seu ID (ex: 'T1110'), ou None."""
    if database is None:
        database = load_mitre_database()
    return database.get(technique_id)


def get_techniques_for_detection(detection_type: str, database: Optional[dict] = None) -> list[dict]:
    """
    Retorna a lista de tecnicas MITRE associadas a um tipo de deteccao
    (ex: 'brute_force'), incluindo o ID de cada tecnica no dicionario
    retornado. Se nao houver associacao conhecida, retorna lista vazia.
    """
    if database is None:
        database = load_mitre_database()

    technique_ids = DETECTION_TO_TECHNIQUE.get(detection_type, [])
    techniques = []
    for technique_id in technique_ids:
        technique = database.get(technique_id)
        if technique:
            techniques.append({"id": technique_id, **technique})
    return techniques
