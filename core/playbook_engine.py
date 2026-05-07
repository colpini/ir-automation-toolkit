"""
PlaybookEngine — Carrega e executa playbooks YAML.

Fluxo:
  1. Carrega o playbook YAML correspondente ao tipo de incidente
  2. Renderiza os templates {{ iocs.src_ip }} com os dados reais
  3. Executa cada step chamando o Action correspondente
  4. Retorna um ExecutionReport com o resultado de cada step
"""

import yaml
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

from core.actions import ActionRunner


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class StepResult:
    step_id: str
    action: str
    description: str
    status: str        # success, skipped, error
    output: str
    executed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ExecutionReport:
    playbook_name: str
    incident_type: str
    severity: str
    total_steps: int
    executed: int
    skipped: int
    errors: int
    steps: List[StepResult]
    started_at: str
    finished_at: str = ""


class PlaybookEngine:
    """
    Localiza, carrega e executa playbooks YAML.
    Suporta templates Jinja-like simples com {{ variavel }}.
    """

    def __init__(self, playbooks_dir: str = "playbooks"):
        self.playbooks_dir = Path(playbooks_dir)
        self.action_runner = ActionRunner()

    def run(self, incident, alert: dict) -> Optional[ExecutionReport]:
        """
        Ponto de entrada principal.
        Recebe o IncidentClassification e o alerta normalizado.
        """
        playbook_file = self.playbooks_dir / incident.recommended_playbook

        # Fallback para genérico se não encontrar o playbook
        if not playbook_file.exists():
            playbook_file = self.playbooks_dir / "playbook_generic.yaml"

        if not playbook_file.exists():
            print(f"  ❌ Nenhum playbook encontrado em {self.playbooks_dir}")
            return None

        playbook = self._load_playbook(playbook_file)
        if not playbook:
            return None

        # Verifica se a severidade do incidente atinge o threshold do playbook
        threshold = playbook.get("severity_threshold", "low")
        if not self._meets_threshold(incident.severity, threshold):
            print(f"  ⏭️  Playbook ignorado — severidade '{incident.severity}' abaixo do threshold '{threshold}'")
            return None

        print(f"\n  {'─'*56}")
        print(f"  🎬 EXECUTANDO PLAYBOOK: {playbook['name']}")
        print(f"  {'─'*56}")
        print(f"  📄 {playbook.get('description', '')}")
        print(f"  🔢 Steps: {len(playbook.get('steps', []))}\n")

        # Monta o contexto de template
        context = self._build_context(incident, alert)

        started_at = datetime.utcnow().isoformat()
        step_results = []

        for step in playbook.get("steps", []):
            result = self._execute_step(step, context)
            step_results.append(result)

        finished_at = datetime.utcnow().isoformat()

        report = ExecutionReport(
            playbook_name=playbook["name"],
            incident_type=incident.incident_type,
            severity=incident.severity,
            total_steps=len(step_results),
            executed=sum(1 for s in step_results if s.status == "success"),
            skipped=sum(1 for s in step_results if s.status == "skipped"),
            errors=sum(1 for s in step_results if s.status == "error"),
            steps=step_results,
            started_at=started_at,
            finished_at=finished_at,
        )

        self._print_execution_summary(report)
        return report

    def _load_playbook(self, path: Path) -> Optional[dict]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"  ❌ Erro ao carregar playbook: {e}")
            return None

    def _build_context(self, incident, alert: dict) -> dict:
        """Monta o dicionário de contexto para renderizar os templates."""
        return {
            "iocs": incident.iocs,
            "alert": alert,
            "incident": {
                "type": incident.incident_type,
                "severity": incident.severity,
                "severity_score": incident.severity_score,
                "confidence": incident.confidence,
                "playbook": incident.recommended_playbook,
            }
        }

    def _render(self, value, context: dict) -> str:
        """
        Renderiza templates simples: {{ iocs.src_ip }}, {{ alert.agent_name }}, etc.
        Suporta acesso aninhado com ponto.
        """
        if not isinstance(value, str):
            return str(value)

        def replacer(match):
            key_path = match.group(1).strip()
            parts = key_path.split(".")
            obj = context
            try:
                for part in parts:
                    if isinstance(obj, dict):
                        obj = obj.get(part, "")
                    else:
                        obj = getattr(obj, part, "")
                return str(obj) if obj else f"[{key_path}: N/A]"
            except Exception:
                return f"[{key_path}: erro]"

        return re.sub(r"\{\{\s*([\w\.]+)\s*\}\}", replacer, value)

    def _render_params(self, params: dict, context: dict) -> dict:
        """Renderiza todos os valores de um dicionário de params."""
        rendered = {}
        for key, value in params.items():
            if isinstance(value, str):
                rendered[key] = self._render(value, context)
            elif isinstance(value, dict):
                rendered[key] = self._render_params(value, context)
            else:
                rendered[key] = value
        return rendered

    def _execute_step(self, step: dict, context: dict) -> StepResult:
        step_id = step.get("id", "unknown")
        action = step.get("action", "")
        description = step.get("description", "")
        params = step.get("params", {})

        print(f"  ▶ [{step_id}] {description}")

        rendered_params = self._render_params(params, context)

        try:
            output = self.action_runner.run(action, rendered_params)
            status = "success"
            print(f"    ✅ {output}")
        except Exception as e:
            output = str(e)
            status = "error"
            print(f"    ❌ Erro: {output}")

        return StepResult(
            step_id=step_id,
            action=action,
            description=description,
            status=status,
            output=output,
        )

    def _meets_threshold(self, severity: str, threshold: str) -> bool:
        try:
            return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(threshold)
        except ValueError:
            return True

    def _print_execution_summary(self, report: ExecutionReport):
        print(f"\n  {'─'*56}")
        print(f"  📊 RESUMO DA EXECUÇÃO")
        print(f"  {'─'*56}")
        print(f"  ✅ Executados : {report.executed}/{report.total_steps}")
        if report.skipped:
            print(f"  ⏭️  Ignorados  : {report.skipped}")
        if report.errors:
            print(f"  ❌ Erros      : {report.errors}")
        print(f"  ⏱️  Duração    : ~{self._calc_duration(report.started_at, report.finished_at)}ms")

    def _calc_duration(self, start: str, end: str) -> int:
        try:
            from datetime import datetime
            fmt = "%Y-%m-%dT%H:%M:%S.%f"
            delta = datetime.fromisoformat(end) - datetime.fromisoformat(start)
            return int(delta.total_seconds() * 1000)
        except Exception:
            return 0
