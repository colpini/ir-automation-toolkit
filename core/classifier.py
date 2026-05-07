"""
IncidentClassifier — Classifica o tipo de incidente baseado no alerta normalizado.

Usa um sistema de regras com score ponderado para identificar:
  - Brute Force / Credential Stuffing
  - Malware / Ransomware
  - Exfiltração de dados
  - Escalada de privilégios
  - Reconhecimento / Scanning
  - Acesso suspeito
  - Incidente desconhecido
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime


@dataclass
class IncidentClassification:
    incident_type: str
    confidence: float          # 0.0 a 1.0
    severity: str              # critical, high, medium, low, info
    severity_score: int        # 0-100
    matched_rules: List[str]
    recommended_playbook: str
    iocs: Dict                 # Indicators of Compromise extraídos
    classified_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class IncidentClassifier:
    """
    Classifica incidentes usando regras baseadas em:
      - rule_id / groups do alerta
      - palavras-chave na descrição
      - campos específicos (src_ip, username, file_hash, etc.)
    """

    # Definição dos tipos de incidentes suportados
    INCIDENT_TYPES = {
        "brute_force": {
            "description": "Tentativas repetidas de autenticação",
            "default_severity": "high",
            "tags": ["authentication", "credential", "login"],
            "playbook": "playbook_brute_force.yaml",
        },
        "malware": {
            "description": "Arquivo ou processo malicioso detectado",
            "default_severity": "critical",
            "tags": ["malware", "ransomware", "trojan", "virus"],
            "playbook": "playbook_malware.yaml",
        },
        "data_exfiltration": {
            "description": "Suspeita de vazamento/exfiltração de dados",
            "default_severity": "critical",
            "tags": ["exfil", "data_loss", "transfer"],
            "playbook": "playbook_exfiltration.yaml",
        },
        "privilege_escalation": {
            "description": "Tentativa de escalada de privilégios",
            "default_severity": "high",
            "tags": ["privilege", "sudo", "admin", "root"],
            "playbook": "playbook_privilege_escalation.yaml",
        },
        "reconnaissance": {
            "description": "Atividade de scanning ou reconhecimento",
            "default_severity": "medium",
            "tags": ["scan", "recon", "enumeration", "nmap"],
            "playbook": "playbook_reconnaissance.yaml",
        },
        "suspicious_access": {
            "description": "Acesso suspeito a recursos ou sistemas",
            "default_severity": "medium",
            "tags": ["access", "unauthorized", "anomaly"],
            "playbook": "playbook_suspicious_access.yaml",
        },
        "unknown": {
            "description": "Tipo de incidente não identificado",
            "default_severity": "low",
            "tags": [],
            "playbook": "playbook_generic.yaml",
        },
    }

    # Regras de classificação com pesos
    CLASSIFICATION_RULES = [
        # Brute Force
        {"type": "brute_force", "weight": 0.9, "match": "groups", "values": ["authentication_failures", "brute_force", "pam", "sshd"]},
        {"type": "brute_force", "weight": 0.8, "match": "description_keywords", "values": ["brute force", "multiple auth", "failed login", "invalid user", "failed password", "authentication failure"]},
        {"type": "brute_force", "weight": 0.7, "match": "rule_id_prefix", "values": ["5551", "5710", "5712", "5716", "5720", "5760"]},

        # Malware
        {"type": "malware", "weight": 0.95, "match": "groups", "values": ["malware", "ransomware", "trojan", "rootkit", "virus"]},
        {"type": "malware", "weight": 0.85, "match": "description_keywords", "values": ["malware", "ransomware", "trojan", "virus", "infected", "malicious file", "eicar", "suspicious binary"]},
        {"type": "malware", "weight": 0.7, "match": "has_field", "values": ["file_hash"]},

        # Exfiltração
        {"type": "data_exfiltration", "weight": 0.9, "match": "groups", "values": ["data_exfiltration", "data_loss", "exfil"]},
        {"type": "data_exfiltration", "weight": 0.8, "match": "description_keywords", "values": ["exfiltration", "data transfer", "large upload", "unusual outbound", "data exfil", "sensitive data"]},

        # Escalada de Privilégios
        {"type": "privilege_escalation", "weight": 0.9, "match": "groups", "values": ["privilege_escalation", "sudo", "su"]},
        {"type": "privilege_escalation", "weight": 0.8, "match": "description_keywords", "values": ["privilege escalation", "sudo", "root access", "admin rights", "privilege abuse", "setuid"]},
        {"type": "privilege_escalation", "weight": 0.6, "match": "rule_id_prefix", "values": ["5401", "5402", "5403"]},

        # Reconhecimento
        {"type": "reconnaissance", "weight": 0.85, "match": "groups", "values": ["recon", "scan", "nmap", "enumeration"]},
        {"type": "reconnaissance", "weight": 0.75, "match": "description_keywords", "values": ["port scan", "network scan", "reconnaissance", "enumeration", "nmap", "masscan"]},

        # Acesso Suspeito
        {"type": "suspicious_access", "weight": 0.7, "match": "groups", "values": ["access_control", "unauthorized", "anomaly"]},
        {"type": "suspicious_access", "weight": 0.65, "match": "description_keywords", "values": ["unauthorized access", "anomalous login", "unusual access", "off-hours login", "geographic anomaly"]},
    ]

    def classify(self, alert: dict) -> IncidentClassification:
        """Classifica o alerta e retorna um IncidentClassification."""
        scores = {itype: 0.0 for itype in self.INCIDENT_TYPES}
        matched_rules = []

        for rule in self.CLASSIFICATION_RULES:
            match, rule_desc = self._apply_rule(rule, alert)
            if match:
                scores[rule["type"]] += rule["weight"]
                matched_rules.append(rule_desc)

        # Pega o tipo com maior score
        best_type = max(scores, key=scores.get)
        best_score = scores[best_type]

        if best_score == 0:
            best_type = "unknown"
            confidence = 0.0
        else:
            # Normaliza a confiança (0-1)
            max_possible = sum(r["weight"] for r in self.CLASSIFICATION_RULES if r["type"] == best_type)
            confidence = min(best_score / max_possible, 1.0)

        type_info = self.INCIDENT_TYPES[best_type]
        severity, severity_score = self._calculate_severity(alert, best_type, confidence)
        iocs = self._extract_iocs(alert)

        return IncidentClassification(
            incident_type=best_type,
            confidence=round(confidence, 2),
            severity=severity,
            severity_score=severity_score,
            matched_rules=matched_rules,
            recommended_playbook=type_info["playbook"],
            iocs=iocs,
        )

    def _apply_rule(self, rule: dict, alert: dict):
        """Aplica uma regra ao alerta. Retorna (match: bool, description: str)."""
        match_type = rule["match"]
        values = [v.lower() for v in rule["values"]]
        itype = rule["type"]

        if match_type == "groups":
            alert_groups = [g.lower() for g in alert.get("groups", [])]
            for v in values:
                if v in alert_groups:
                    return True, f"[{itype}] Grupo '{v}' encontrado nos grupos do alerta"

        elif match_type == "description_keywords":
            desc = alert.get("rule_description", "").lower()
            for v in values:
                if v in desc:
                    return True, f"[{itype}] Keyword '{v}' encontrada na descrição"

        elif match_type == "rule_id_prefix":
            rule_id = alert.get("rule_id", "")
            for v in values:
                if rule_id.startswith(v):
                    return True, f"[{itype}] Rule ID '{rule_id}' tem prefixo '{v}'"

        elif match_type == "has_field":
            for v in values:
                if alert.get(v):
                    return True, f"[{itype}] Campo '{v}' presente no alerta"

        return False, ""

    def _calculate_severity(self, alert: dict, incident_type: str, confidence: float):
        """Calcula a severidade final considerando o nível do alerta e o tipo."""
        base_level = alert.get("severity_level", 0)

        # Mapa de nível Wazuh para score
        level_score = min(base_level * 6, 90)

        # Boost por tipo crítico
        type_boosts = {"malware": 15, "data_exfiltration": 15, "brute_force": 5, "privilege_escalation": 10}
        boost = type_boosts.get(incident_type, 0)

        # Boost por confiança
        confidence_boost = int(confidence * 10)

        final_score = min(level_score + boost + confidence_boost, 100)

        if final_score >= 80:
            severity = "critical"
        elif final_score >= 60:
            severity = "high"
        elif final_score >= 40:
            severity = "medium"
        elif final_score >= 20:
            severity = "low"
        else:
            severity = "info"

        return severity, final_score

    def _extract_iocs(self, alert: dict) -> dict:
        """Extrai Indicators of Compromise do alerta normalizado."""
        iocs = {}
        if alert.get("src_ip"):
            iocs["src_ip"] = alert["src_ip"]
        if alert.get("dst_ip"):
            iocs["dst_ip"] = alert["dst_ip"]
        if alert.get("username"):
            iocs["username"] = alert["username"]
        if alert.get("file_hash"):
            iocs["file_hash"] = alert["file_hash"]
        if alert.get("file_path"):
            iocs["file_path"] = alert["file_path"]
        if alert.get("process"):
            iocs["process"] = alert["process"]
        return iocs

    def get_supported_types(self) -> dict:
        return self.INCIDENT_TYPES
