"""
AlertParser — Lê e normaliza alertas de diferentes fontes.

Suporta:
  - Alertas do Wazuh (formato nativo)
  - Alertas genéricos (formato IR Toolkit)
  - Logs brutos em JSON
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Optional


class AlertParser:
    """
    Faz o parse de um arquivo de alerta JSON e retorna
    um dicionário normalizado (NormalizedAlert).
    """

    SUPPORTED_SOURCES = ["wazuh", "generic", "syslog", "windows_event"]

    def parse(self, file_path: Path) -> Optional[dict]:
        """
        Lê o arquivo e detecta automaticamente o formato.
        Retorna um NormalizedAlert ou None em caso de erro.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except json.JSONDecodeError as e:
            print(f"❌ JSON inválido: {e}")
            return None
        except Exception as e:
            print(f"❌ Erro ao ler arquivo: {e}")
            return None

        source = self._detect_source(raw)
        print(f"  ✅ Fonte detectada: {source.upper()}")

        normalized = self._normalize(raw, source)
        return normalized

    def _detect_source(self, raw: dict) -> str:
        """Detecta a origem do alerta pelo formato do JSON."""
        if "rule" in raw and "agent" in raw and "manager" in raw:
            return "wazuh"
        elif "event_id" in raw and "source" in raw:
            return "generic"
        elif "EventID" in raw or "Channel" in raw:
            return "windows_event"
        else:
            return "generic"

    def _normalize(self, raw: dict, source: str) -> dict:
        """
        Transforma o alerta bruto em um NormalizedAlert padronizado.
        Esse formato é usado pelo Classificador e pelo motor de Playbooks.
        """
        if source == "wazuh":
            return self._normalize_wazuh(raw)
        elif source == "windows_event":
            return self._normalize_windows(raw)
        else:
            return self._normalize_generic(raw)

    def _normalize_wazuh(self, raw: dict) -> dict:
        rule = raw.get("rule", {})
        agent = raw.get("agent", {})
        data = raw.get("data", {})

        return {
            "source": "wazuh",
            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
            "alert_id": raw.get("id", "unknown"),
            "rule_id": str(rule.get("id", "")),
            "rule_description": rule.get("description", ""),
            "severity_level": rule.get("level", 0),
            "groups": rule.get("groups", []),
            "agent_name": agent.get("name", "unknown"),
            "agent_ip": agent.get("ip", "0.0.0.0"),
            "src_ip": data.get("srcip", data.get("src_ip", "")),
            "dst_ip": data.get("dstip", data.get("dst_ip", "")),
            "username": data.get("srcuser", data.get("user", "")),
            "process": data.get("process", ""),
            "file_path": data.get("file", ""),
            "file_hash": data.get("md5", data.get("sha256", "")),
            "raw_message": raw.get("full_log", ""),
            "extra": data,
        }

    def _normalize_generic(self, raw: dict) -> dict:
        return {
            "source": raw.get("source", "generic"),
            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
            "alert_id": raw.get("event_id", raw.get("id", "unknown")),
            "rule_id": str(raw.get("rule_id", "")),
            "rule_description": raw.get("description", raw.get("message", "")),
            "severity_level": raw.get("severity", raw.get("level", 0)),
            "groups": raw.get("groups", raw.get("tags", [])),
            "agent_name": raw.get("hostname", raw.get("host", "unknown")),
            "agent_ip": raw.get("agent_ip", ""),
            "src_ip": raw.get("src_ip", raw.get("source_ip", "")),
            "dst_ip": raw.get("dst_ip", raw.get("destination_ip", "")),
            "username": raw.get("username", raw.get("user", "")),
            "process": raw.get("process", raw.get("process_name", "")),
            "file_path": raw.get("file_path", raw.get("file", "")),
            "file_hash": raw.get("file_hash", raw.get("md5", raw.get("sha256", ""))),
            "raw_message": raw.get("raw_message", raw.get("log", "")),
            "extra": raw.get("extra", {}),
        }

    def _normalize_windows(self, raw: dict) -> dict:
        return {
            "source": "windows_event",
            "timestamp": raw.get("TimeCreated", datetime.utcnow().isoformat()),
            "alert_id": str(raw.get("EventID", "unknown")),
            "rule_id": str(raw.get("EventID", "")),
            "rule_description": raw.get("Message", ""),
            "severity_level": self._windows_level_map(raw.get("Level", 0)),
            "groups": ["windows"],
            "agent_name": raw.get("Computer", "unknown"),
            "agent_ip": "",
            "src_ip": raw.get("IpAddress", ""),
            "dst_ip": "",
            "username": raw.get("SubjectUserName", raw.get("TargetUserName", "")),
            "process": raw.get("ProcessName", ""),
            "file_path": "",
            "file_hash": "",
            "raw_message": raw.get("Message", ""),
            "extra": raw,
        }

    def _windows_level_map(self, level: int) -> int:
        mapping = {1: 14, 2: 12, 3: 8, 4: 5, 0: 3}
        return mapping.get(level, 5)
