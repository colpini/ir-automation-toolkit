"""
ActionRunner — Executa as ações dos playbooks de forma simulada localmente.

Ações disponíveis:
  - block_ip     → Registra IP em blocklist local (arquivo)
  - notify       → Simula notificação no terminal + arquivo de log
  - log_case     → Cria/atualiza o log de casos de incidentes
"""

import json
from pathlib import Path
from datetime import datetime


BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RED = "\033[91m"
DIM = "\033[2m"
RESET = "\033[0m"

OUTPUTS_DIR = Path("reports")


class ActionRunner:
    """
    Despacha a ação correta baseado no nome recebido do playbook.
    """

    def run(self, action: str, params: dict) -> str:
        OUTPUTS_DIR.mkdir(exist_ok=True)

        handlers = {
            "block_ip":  self._action_block_ip,
            "notify":    self._action_notify,
            "log_case":  self._action_log_case,
        }

        handler = handlers.get(action)
        if not handler:
            raise ValueError(f"Ação desconhecida: '{action}'")

        return handler(params)

    # ─────────────────────────────────────────────
    # AÇÃO: block_ip
    # Simula bloqueio de IP gravando em blocklist.txt
    # ─────────────────────────────────────────────
    def _action_block_ip(self, params: dict) -> str:
        target_ip = params.get("target", "")
        reason = params.get("reason", "Bloqueado por playbook IR")
        duration_hours = params.get("duration_hours", 24)

        if not target_ip or target_ip in ("", "[iocs.dst_ip: N/A]", "[iocs.src_ip: N/A]"):
            return "IP não disponível — step ignorado"

        blocklist_path = OUTPUTS_DIR / "blocklist.txt"
        timestamp = datetime.utcnow().isoformat()
        expires = f"+{duration_hours}h"

        entry = f"{timestamp} | BLOCK | {target_ip:<20} | {expires:<8} | {reason}\n"

        with open(blocklist_path, "a", encoding="utf-8") as f:
            f.write(entry)

        return f"IP {BOLD}{target_ip}{RESET} bloqueado por {duration_hours}h → {DIM}{blocklist_path}{RESET}"

    # ─────────────────────────────────────────────
    # AÇÃO: notify
    # Simula notificação exibindo no terminal + gravando em notifications.log
    # ─────────────────────────────────────────────
    def _action_notify(self, params: dict) -> str:
        channel = params.get("channel", "soc-alerts")
        priority = params.get("priority", "medium")
        message = params.get("message", "").strip()

        notif_path = OUTPUTS_DIR / "notifications.log"
        timestamp = datetime.utcnow().isoformat()

        priority_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(priority, "⚪")

        # Exibe no terminal
        print(f"\n    {CYAN}┌─ #{channel} [{priority.upper()}] {priority_icon}{RESET}")
        for line in message.splitlines():
            print(f"    {CYAN}│{RESET} {line}")
        print(f"    {CYAN}└─ {DIM}{timestamp}{RESET}")

        # Grava no arquivo
        with open(notif_path, "a", encoding="utf-8") as f:
            f.write(f"\n[{timestamp}] CHANNEL=#{channel} PRIORITY={priority.upper()}\n")
            f.write(message + "\n")
            f.write("─" * 60 + "\n")

        return f"Notificação enviada para #{channel} → {DIM}{notif_path}{RESET}"

    # ─────────────────────────────────────────────
    # AÇÃO: log_case
    # Cria/atualiza o arquivo cases.json com o incidente
    # ─────────────────────────────────────────────
    def _action_log_case(self, params: dict) -> str:
        title = params.get("title", "Incidente sem título")
        severity = params.get("severity", "unknown")
        iocs = params.get("iocs", {})
        notes = params.get("notes", "")

        cases_path = OUTPUTS_DIR / "cases.json"
        timestamp = datetime.utcnow().isoformat()

        # Carrega casos existentes
        cases = []
        if cases_path.exists():
            try:
                with open(cases_path, "r", encoding="utf-8") as f:
                    cases = json.load(f)
            except Exception:
                cases = []

        case_id = f"CASE-{len(cases) + 1:04d}"

        new_case = {
            "case_id": case_id,
            "title": title,
            "severity": severity,
            "status": "open",
            "created_at": timestamp,
            "iocs": iocs if isinstance(iocs, dict) else {},
            "notes": notes,
        }

        cases.append(new_case)

        with open(cases_path, "w", encoding="utf-8") as f:
            json.dump(cases, f, indent=2, ensure_ascii=False)

        return f"Caso {BOLD}{case_id}{RESET} registrado → {DIM}{cases_path}{RESET}"
