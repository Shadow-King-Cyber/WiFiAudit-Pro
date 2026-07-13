"""Exportador JSON — serializa reportes de auditoría a JSON machine-readable."""

from __future__ import annotations

import json
from pathlib import Path

from .report_builder import AuditReport


def export_json(report: AuditReport, output_path: str | Path) -> Path:
    """Escribe el reporte como un archivo JSON formateado.

    Devuelve la ruta del archivo escrito.
    """
    path = Path(output_path)
    # Crear directorio padre si no existe
    path.parent.mkdir(parents=True, exist_ok=True)

    # Construir diccionario de datos del reporte
    data = {
        "title": report.title,
        "generated_at": report.generated_at,
        "summary": report.summary,
        "networks": [
            {
                "bssid": n.bssid,
                "ssid": n.ssid,
                "channel": n.channel,
                "encryption": n.encryption,
                "signal_strength": n.signal_strength,
                "wps_enabled": n.wps_enabled,
                "default_creds_suspected": n.default_creds_suspected,
                "vendor": n.vendor,
                "risk_score": n.risk_score,
                "risk_level": n.risk_level,
                "mitre_techniques": n.mitre_techniques,
                "hardening_recommendations": n.hardening_recommendations,
                "in_scope": n.in_scope,
            }
            for n in report.networks
        ],
    }

    # Escribir JSON con indentación para legibilidad
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    return path
