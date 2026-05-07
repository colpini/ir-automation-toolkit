"""
Reporter — Formata e exibe o resultado da classificação no terminal.
"""

from datetime import datetime


SEVERITY_COLORS = {
    "critical": "\033[91m",   # Vermelho brilhante
    "high":     "\033[31m",   # Vermelho
    "medium":   "\033[33m",   # Amarelo
    "low":      "\033[34m",   # Azul
    "info":     "\033[36m",   # Ciano
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
DIM = "\033[2m"


def print_incident_summary(incident, alert: dict, verbose: bool = False):
    sev = incident.severity
    color = SEVERITY_COLORS.get(sev, "")
    icon = SEVERITY_ICONS.get(sev, "❓")

    # Barra de progresso para score
    bar = _progress_bar(incident.severity_score)
    confidence_pct = int(incident.confidence * 100)

    print(f"  {'─'*56}")
    print(f"  {BOLD}📌 CLASSIFICAÇÃO DO INCIDENTE{RESET}")
    print(f"  {'─'*56}")
    print(f"  Tipo        : {BOLD}{incident.incident_type.upper().replace('_', ' ')}{RESET}")
    print(f"  Severidade  : {color}{BOLD}{icon}  {sev.upper()}{RESET}  {bar}  ({incident.severity_score}/100)")
    print(f"  Confiança   : {_confidence_bar(confidence_pct)}  {confidence_pct}%")
    print(f"  Playbook    : {GREEN}{incident.recommended_playbook}{RESET}")
    print(f"  Classificado: {DIM}{incident.classified_at}{RESET}")

    # IOCs
    if incident.iocs:
        print(f"\n  {'─'*56}")
        print(f"  {BOLD}🎯 INDICATORS OF COMPROMISE (IOCs){RESET}")
        print(f"  {'─'*56}")
        for key, val in incident.iocs.items():
            label = key.replace("_", " ").title()
            print(f"  {label:<14}: {val}")

    # Regras que fizeram match
    if incident.matched_rules:
        print(f"\n  {'─'*56}")
        print(f"  {BOLD}📋 REGRAS ATIVADAS ({len(incident.matched_rules)}){RESET}")
        print(f"  {'─'*56}")
        for rule in incident.matched_rules:
            print(f"  ✓ {DIM}{rule}{RESET}")

    # Contexto do alerta
    print(f"\n  {'─'*56}")
    print(f"  {BOLD}📊 CONTEXTO DO ALERTA{RESET}")
    print(f"  {'─'*56}")
    print(f"  Fonte       : {alert.get('source', 'N/A').upper()}")
    print(f"  Host/Agente : {alert.get('agent_name', 'N/A')}")
    print(f"  Timestamp   : {alert.get('timestamp', 'N/A')}")
    if alert.get("rule_description"):
        desc = alert["rule_description"]
        if len(desc) > 60:
            desc = desc[:57] + "..."
        print(f"  Descrição   : {desc}")
    if alert.get("rule_id"):
        print(f"  Rule ID     : {alert.get('rule_id')}")

    # Verbose: exibe alert completo
    if verbose:
        import json
        print(f"\n  {'─'*56}")
        print(f"  {BOLD}🔬 ALERTA NORMALIZADO (raw){RESET}")
        print(f"  {'─'*56}")
        print(json.dumps(alert, indent=4, ensure_ascii=False))

    # Próximos passos
    print(f"\n  {'─'*56}")
    print(f"  {BOLD}⚡ PRÓXIMOS PASSOS SUGERIDOS{RESET}")
    print(f"  {'─'*56}")
    for step in _get_next_steps(incident.incident_type, sev):
        print(f"  → {step}")

    print(f"\n{'='*60}\n")


def _progress_bar(score: int, width: int = 12) -> str:
    filled = int((score / 100) * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}]"


def _confidence_bar(pct: int, width: int = 12) -> str:
    filled = int((pct / 100) * width)
    bar = "▓" * filled + "░" * (width - filled)
    return f"[{bar}]"


def _get_next_steps(incident_type: str, severity: str) -> list:
    steps = {
        "brute_force": [
            "Bloquear IP de origem no firewall",
            "Verificar se houve login bem-sucedido após as tentativas",
            "Resetar credenciais do usuário alvo",
            "Habilitar MFA se ainda não estiver ativo",
        ],
        "malware": [
            "Isolar o host da rede imediatamente",
            "Enviar hash do arquivo para VirusTotal",
            "Preservar imagem forense do sistema",
            "Verificar processos em execução e conexões ativas",
        ],
        "data_exfiltration": [
            "Bloquear IP de destino no firewall",
            "Identificar quais dados foram transferidos",
            "Notificar equipe de privacidade/compliance",
            "Revogar credenciais do usuário envolvido",
        ],
        "privilege_escalation": [
            "Revisar logs de sudo/su no host afetado",
            "Verificar arquivos modificados com permissões elevadas",
            "Auditar membros do grupo admin/root",
            "Resetar a sessão ativa do usuário",
        ],
        "reconnaissance": [
            "Bloquear IP de origem no perímetro",
            "Verificar se o scan identificou serviços vulneráveis",
            "Revisar regras de firewall expostas",
            "Correlacionar com outros alertas do mesmo IP",
        ],
        "suspicious_access": [
            "Confirmar com o usuário se o acesso é legítimo",
            "Revisar logs de acesso nas últimas 24h",
            "Verificar localização geográfica do login",
            "Considerar bloqueio temporário da conta",
        ],
        "unknown": [
            "Analisar o alerta manualmente",
            "Escalar para o analista sênior do SOC",
            "Correlacionar com outros alertas recentes",
        ],
    }

    base = steps.get(incident_type, steps["unknown"])

    if severity == "critical":
        base = ["🚨 ESCALAR IMEDIATAMENTE — Incidente crítico!"] + base

    return base
