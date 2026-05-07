"""
ThreatIntel — Integração com APIs externas de Threat Intelligence.

Serviços:
  - VirusTotal  → verifica hashes de arquivos e reputação de IPs
  - AbuseIPDB   → verifica reputação e histórico de abuso de IPs
"""

import requests
import time
from datetime import datetime


BOLD  = "\033[1m"
RED   = "\033[91m"
YELLOW= "\033[33m"
GREEN = "\033[92m"
CYAN  = "\033[36m"
DIM   = "\033[2m"
RESET = "\033[0m"


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}

    def check_hash(self, file_hash: str) -> dict:
        """Verifica reputação de um hash (MD5, SHA1 ou SHA256)."""
        url = f"{self.BASE_URL}/files/{file_hash}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=10)
            if resp.status_code == 404:
                return {"found": False, "hash": file_hash, "message": "Hash não encontrado na base do VirusTotal"}
            if resp.status_code == 401:
                return {"found": False, "hash": file_hash, "error": "API key inválida"}
            resp.raise_for_status()
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            names = data["data"]["attributes"].get("meaningful_name", "desconhecido")
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            return {
                "found": True,
                "hash": file_hash,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": stats.get("undetected", 0),
                "total_engines": total,
                "detection_rate": f"{malicious}/{total}",
                "file_name": names,
                "verdict": self._hash_verdict(malicious, total),
            }
        except requests.RequestException as e:
            return {"found": False, "hash": file_hash, "error": str(e)}

    def check_ip(self, ip: str) -> dict:
        """Verifica reputação de um IP no VirusTotal."""
        url = f"{self.BASE_URL}/ip_addresses/{ip}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=10)
            if resp.status_code == 404:
                return {"found": False, "ip": ip, "message": "IP não encontrado"}
            if resp.status_code == 401:
                return {"found": False, "ip": ip, "error": "API key inválida"}
            resp.raise_for_status()
            data = resp.json()
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())

            return {
                "found": True,
                "ip": ip,
                "malicious": malicious,
                "total_engines": total,
                "detection_rate": f"{malicious}/{total}",
                "country": attrs.get("country", "N/A"),
                "as_owner": attrs.get("as_owner", "N/A"),
                "reputation": attrs.get("reputation", 0),
                "verdict": self._hash_verdict(malicious, total),
            }
        except requests.RequestException as e:
            return {"found": False, "ip": ip, "error": str(e)}

    def _hash_verdict(self, malicious: int, total: int) -> str:
        if total == 0:
            return "unknown"
        rate = malicious / total
        if malicious >= 10 or rate > 0.3:
            return "malicious"
        elif malicious >= 3 or rate > 0.1:
            return "suspicious"
        elif malicious > 0:
            return "low_risk"
        else:
            return "clean"


class AbuseIPDBClient:
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"Key": api_key, "Accept": "application/json"}

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """Verifica o histórico de abuso de um IP."""
        if not ip or ip in ("", "0.0.0.0"):
            return {"found": False, "ip": ip, "message": "IP inválido ou não disponível"}
        url = f"{self.BASE_URL}/check"
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True}
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=10)
            if resp.status_code == 401:
                return {"found": False, "ip": ip, "error": "API key inválida"}
            if resp.status_code == 422:
                return {"found": False, "ip": ip, "message": "IP privado ou inválido (não verificável)"}
            resp.raise_for_status()
            data = resp.json().get("data", {})

            score = data.get("abuseConfidenceScore", 0)
            return {
                "found": True,
                "ip": ip,
                "abuse_score": score,
                "total_reports": data.get("totalReports", 0),
                "distinct_users": data.get("numDistinctUsers", 0),
                "country": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "domain": data.get("domain", "N/A"),
                "last_reported": data.get("lastReportedAt", "N/A"),
                "is_tor": data.get("isTor", False),
                "usage_type": data.get("usageType", "N/A"),
                "verdict": self._abuse_verdict(score),
            }
        except requests.RequestException as e:
            return {"found": False, "ip": ip, "error": str(e)}

    def _abuse_verdict(self, score: int) -> str:
        if score >= 80:
            return "malicious"
        elif score >= 40:
            return "suspicious"
        elif score >= 10:
            return "low_risk"
        else:
            return "clean"


def print_vt_hash_result(result: dict):
    """Exibe resultado da verificação de hash do VirusTotal."""
    print(f"\n  {'─'*56}")
    print(f"  {BOLD}🦠 VIRUSTOTAL — Hash Check{RESET}")
    print(f"  {'─'*56}")

    if not result.get("found"):
        msg = result.get("message") or result.get("error", "Erro desconhecido")
        print(f"  ⚠️  {msg}")
        return

    verdict = result.get("verdict", "unknown")
    verdict_display = _verdict_badge(verdict)

    print(f"  Hash            : {DIM}{result['hash']}{RESET}")
    print(f"  Nome do arquivo : {result.get('file_name', 'N/A')}")
    print(f"  Detecções       : {BOLD}{result['detection_rate']}{RESET} engines")
    print(f"  Maliciosos      : {RED}{result['malicious']}{RESET}")
    print(f"  Suspeitos       : {YELLOW}{result.get('suspicious', 0)}{RESET}")
    print(f"  Veredicto       : {verdict_display}")


def print_vt_ip_result(result: dict):
    """Exibe resultado da verificação de IP do VirusTotal."""
    print(f"\n  {'─'*56}")
    print(f"  {BOLD}🔍 VIRUSTOTAL — IP Check{RESET}")
    print(f"  {'─'*56}")

    if not result.get("found"):
        msg = result.get("message") or result.get("error", "Erro desconhecido")
        print(f"  ⚠️  {msg}")
        return

    verdict = result.get("verdict", "unknown")
    print(f"  IP              : {BOLD}{result['ip']}{RESET}")
    print(f"  País            : {result.get('country', 'N/A')}")
    print(f"  AS Owner        : {result.get('as_owner', 'N/A')}")
    print(f"  Detecções       : {BOLD}{result['detection_rate']}{RESET} engines")
    print(f"  Reputação       : {result.get('reputation', 'N/A')}")
    print(f"  Veredicto       : {_verdict_badge(verdict)}")


def print_abuse_result(result: dict):
    """Exibe resultado da verificação de IP do AbuseIPDB."""
    print(f"\n  {'─'*56}")
    print(f"  {BOLD}🛡️  ABUSEIPDB — IP Reputation{RESET}")
    print(f"  {'─'*56}")

    if not result.get("found"):
        msg = result.get("message") or result.get("error", "Erro desconhecido")
        print(f"  ⚠️  {msg}")
        return

    score = result.get("abuse_score", 0)
    score_bar = _score_bar(score)
    verdict = result.get("verdict", "unknown")

    print(f"  IP              : {BOLD}{result['ip']}{RESET}")
    print(f"  Abuse Score     : {score_bar} {BOLD}{score}%{RESET}")
    print(f"  Total Reports   : {result.get('total_reports', 0)}")
    print(f"  Usuários únicos : {result.get('distinct_users', 0)}")
    print(f"  País            : {result.get('country', 'N/A')}")
    print(f"  ISP             : {result.get('isp', 'N/A')}")
    print(f"  Último report   : {DIM}{result.get('last_reported', 'N/A')}{RESET}")
    if result.get("is_tor"):
        print(f"  TOR Exit Node   : {RED}SIM ⚠️{RESET}")
    print(f"  Veredicto       : {_verdict_badge(verdict)}")


def _verdict_badge(verdict: str) -> str:
    badges = {
        "malicious":  f"{RED}{BOLD}🔴 MALICIOSO{RESET}",
        "suspicious": f"{YELLOW}{BOLD}🟡 SUSPEITO{RESET}",
        "low_risk":   f"{YELLOW}🟡 BAIXO RISCO{RESET}",
        "clean":      f"{GREEN}{BOLD}🟢 LIMPO{RESET}",
        "unknown":    f"{DIM}⚪ DESCONHECIDO{RESET}",
    }
    return badges.get(verdict, f"{DIM}⚪ {verdict.upper()}{RESET}")


def _score_bar(score: int, width: int = 12) -> str:
    filled = int((score / 100) * width)
    if score >= 80:
        color = RED
    elif score >= 40:
        color = YELLOW
    else:
        color = GREEN
    bar = "█" * filled + "░" * (width - filled)
    return f"{color}[{bar}]{RESET}"
