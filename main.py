#!/usr/bin/env python3
"""
IR Automation Toolkit - CLI Entry Point
Fase 3: Parser + Classificador + Playbook Engine + Threat Intel
"""

import argparse
import sys
from pathlib import Path
from core.parser import AlertParser
from core.classifier import IncidentClassifier
from core.reporter import print_incident_summary
from core.playbook_engine import PlaybookEngine
from core.threat_intel import (
    VirusTotalClient, AbuseIPDBClient,
    print_vt_hash_result, print_vt_ip_result, print_abuse_result
)

try:
    from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
except ImportError:
    VIRUSTOTAL_API_KEY = ""
    ABUSEIPDB_API_KEY  = ""


def main():
    parser = argparse.ArgumentParser(
        prog="ir-toolkit",
        description="🔵 IR Automation Toolkit — Resposta a Incidentes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python main.py analyze --file alerts/samples/brute_force.json
  python main.py analyze --file alerts/samples/malware.json --intel
  python main.py analyze --file alerts/samples/exfil.json --intel --dry-run
  python main.py check-ip 185.220.101.47
  python main.py check-hash d41d8cd98f00b204e9800998ecf8427e
  python main.py list-types
        """
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze
    ap = subparsers.add_parser("analyze", help="Analisa alerta, classifica e executa playbook")
    ap.add_argument("--file", "-f", required=True, help="Arquivo JSON do alerta")
    ap.add_argument("--verbose", "-v", action="store_true", help="Exibe alerta normalizado completo")
    ap.add_argument("--dry-run", action="store_true", help="Classifica sem executar o playbook")
    ap.add_argument("--intel", "-i", action="store_true", help="Consulta VirusTotal e AbuseIPDB com os IOCs")

    # check-ip
    ip_p = subparsers.add_parser("check-ip", help="Verifica reputação de um IP")
    ip_p.add_argument("ip", help="Endereço IP para verificar")

    # check-hash
    h_p = subparsers.add_parser("check-hash", help="Verifica hash de arquivo no VirusTotal")
    h_p.add_argument("hash", help="Hash MD5/SHA1/SHA256 para verificar")

    # list-types
    subparsers.add_parser("list-types", help="Lista os tipos de incidentes suportados")

    args = parser.parse_args()

    if args.command == "analyze":
        run_analyze(args)
    elif args.command == "check-ip":
        run_check_ip(args.ip)
    elif args.command == "check-hash":
        run_check_hash(args.hash)
    elif args.command == "list-types":
        run_list_types()


def run_analyze(args):
    alert_path = Path(args.file)
    if not alert_path.exists():
        print(f"❌ Arquivo não encontrado: {alert_path}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  🔍 IR TOOLKIT — Analisando alerta")
    print(f"{'='*60}")
    print(f"  📂 Arquivo: {alert_path.name}\n")

    # 1. Parse
    alert = AlertParser().parse(alert_path)
    if not alert:
        print("❌ Falha ao fazer parse do alerta.")
        sys.exit(1)

    # 2. Classificação
    incident = IncidentClassifier().classify(alert)

    # 3. Exibição
    print_incident_summary(incident, alert, verbose=args.verbose)

    # 4. Threat Intel (opcional via --intel)
    if args.intel:
        run_intel_on_iocs(incident.iocs)

    # 5. Playbook
    if args.dry_run:
        print(f"  ⏭️  Modo --dry-run: playbook não executado.\n")
        return

    PlaybookEngine(playbooks_dir="playbooks").run(incident, alert)

    print(f"\n{'='*60}")
    print(f"  📁 Artefatos gerados em: reports/")
    print(f"     • reports/blocklist.txt")
    print(f"     • reports/cases.json")
    print(f"     • reports/notifications.log")
    print(f"{'='*60}\n")


def run_intel_on_iocs(iocs: dict):
    """Consulta Threat Intel para todos os IOCs disponíveis."""
    print(f"\n{'='*60}")
    print(f"  🌐 THREAT INTELLIGENCE — Consultando IOCs")
    print(f"{'='*60}")

    vt  = VirusTotalClient(VIRUSTOTAL_API_KEY)
    ab  = AbuseIPDBClient(ABUSEIPDB_API_KEY)
    ran = False

    # Verifica IPs
    for field in ("src_ip", "dst_ip"):
        ip = iocs.get(field)
        if ip and ip not in ("", "0.0.0.0"):
            label = "Origem" if field == "src_ip" else "Destino"
            print(f"\n  🔎 Verificando IP de {label}: {ip}")
            print_abuse_result(ab.check_ip(ip))
            print_vt_ip_result(vt.check_ip(ip))
            ran = True

    # Verifica hash
    file_hash = iocs.get("file_hash")
    if file_hash:
        print(f"\n  🔎 Verificando hash: {file_hash}")
        print_vt_hash_result(vt.check_hash(file_hash))
        ran = True

    if not ran:
        print(f"\n  ⚠️  Nenhum IOC verificável encontrado (IP ou hash)")

    print(f"\n{'='*60}\n")


def run_check_ip(ip: str):
    """Verifica reputação de um IP avulso."""
    print(f"\n{'='*60}")
    print(f"  🌐 THREAT INTEL — Check IP: {ip}")
    print(f"{'='*60}")
    print_abuse_result(AbuseIPDBClient(ABUSEIPDB_API_KEY).check_ip(ip))
    print_vt_ip_result(VirusTotalClient(VIRUSTOTAL_API_KEY).check_ip(ip))
    print(f"\n{'='*60}\n")


def run_check_hash(file_hash: str):
    """Verifica um hash avulso no VirusTotal."""
    print(f"\n{'='*60}")
    print(f"  🌐 THREAT INTEL — Check Hash: {file_hash}")
    print(f"{'='*60}")
    print_vt_hash_result(VirusTotalClient(VIRUSTOTAL_API_KEY).check_hash(file_hash))
    print(f"\n{'='*60}\n")


def run_list_types():
    classifier = IncidentClassifier()
    print(f"\n{'='*60}")
    print(f"  📋 Tipos de Incidentes Suportados")
    print(f"{'='*60}\n")
    for itype, info in classifier.get_supported_types().items():
        print(f"  🔹 {itype:<20} — {info['description']}")
        print(f"     Severidade padrão: {info['default_severity']}")
        print(f"     Tags: {', '.join(info['tags'])}\n")


if __name__ == "__main__":
    main()
