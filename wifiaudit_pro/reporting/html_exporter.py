"""Exportador HTML — genera un reporte visual HTML con Chart.js."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .report_builder import AuditReport


def export_html(report: AuditReport, output_path: str | Path) -> Path:
    """Renderiza el reporte como un archivo HTML con visualizaciones Chart.js.

    Devuelve la ruta del archivo escrito.
    """
    path = Path(output_path)
    # Crear directorio padre si no existe
    path.parent.mkdir(parents=True, exist_ok=True)

    # Cargar plantilla HTML desde el directorio de templates
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("report_template.html")

    # Renderizar plantilla con los datos del reporte
    html = template.render(
        title=report.title,
        generated_at=report.generated_at,
        summary=report.summary,
        networks=report.networks,
    )

    # Escribir archivo HTML
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return path
