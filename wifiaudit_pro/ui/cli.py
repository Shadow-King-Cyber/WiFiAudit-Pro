"""Interfaz CLI para WiFiAudit-Pro usando Click."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from ..core.scope_manager import ScopeManager
from ..core.audit_logger import AuditLogger
from ..core.config import Config
from ..scanner.passive_scanner import scan_networks, scan_networks_mock
from ..analysis.encryption_analyzer import classify_encryption
from ..analysis.risk_scoring import score_network, ScoringFactors
from ..analysis.wps_detector import detect_wps_from_csv
from ..analysis.default_creds_db import check_default_creds
from ..mitre import map_findings
from ..capture import capture_handshake, capture_handshake_mock
from ..attack import dictionary_attack, dictionary_attack_mock
from ..reporting.report_builder import AuditReport, NetworkReport, build_hardening_recommendations
from ..reporting.json_exporter import export_json
from ..reporting.html_exporter import export_html


@click.group()
@click.option("--scope", default="scope.json", help="Ruta al archivo scope.json")
@click.option("--log", "log_file", default="audit_log.jsonl", help="Ruta al log de auditoría")
@click.pass_context
def cli(ctx: click.Context, scope: str, log_file: str) -> None:
    """WiFiAudit-Pro — Herramienta de Auditoría de Seguridad WiFi."""
    ctx.ensure_object(dict)
    ctx.obj["scope_path"] = scope
    ctx.obj["log_file"] = log_file
    ctx.obj["logger"] = AuditLogger(log_file)


@cli.command()
@click.option("--interface", default="wlan0mon", help="Interfaz en modo monitor")
@click.option("--duration", default=60, help="Duración del escaneo en segundos")
@click.option("--mock", is_flag=True, help="Usar datos simulados (sin hardware)")
@click.pass_context
def scan(ctx: click.Context, interface: str, duration: int, mock: bool) -> None:
    """Escaneo pasivo de redes WiFi cercanas."""
    click.echo(f"[*] Escaneando en {interface} por {duration}s...")

    if mock:
        # Usar datos simulados si se solicita
        results = scan_networks_mock()
    else:
        results = scan_networks(interface=interface, duration=duration)

    click.echo(f"[+] Se encontraron {len(results)} redes:\n")
    for r in results:
        enc = classify_encryption(r.encryption)
        click.echo(f"  {r.bssid}  {r.ssid:<20}  Ch:{r.channel:<3}  {enc:<5}  {r.signal_dbm}dBm")


@cli.command()
@click.option("--bssid", required=True, help="BSSID objetivo")
@click.option("--interface", default="wlan0mon", help="Interfaz en modo monitor")
@click.option("--channel", default=None, type=int, help="Canal a fijar")
@click.option("--timeout", default=120, help="Tiempo límite de captura en segundos")
@click.option("--mock", is_flag=True, help="Usar datos simulados")
@click.pass_context
def capture(ctx: click.Context, bssid: str, interface: str, channel: int | None, timeout: int, mock: bool) -> None:
    """Capturar handshake WPA/WPA2 (requiere BSSID en alcance)."""
    scope = ScopeManager.from_file(ctx.obj["scope_path"])
    logger = ctx.obj["logger"]

    # Verificar autorización antes de cualquier acción activa
    if not scope.is_authorized(bssid):
        logger.log_denied("HANDSHAKE_CAPTURE", bssid)
        click.echo(f"[!] DENEGADO: {bssid} no está en el alcance autorizado.")
        sys.exit(1)

    click.echo(f"[*] Capturando handshake de {bssid}...")
    if mock:
        result = capture_handshake_mock(bssid)
    else:
        result = capture_handshake(
            bssid=bssid, scope=scope, logger=logger,
            interface=interface, channel=channel, timeout=timeout,
        )

    if result.success:
        click.echo(f"[+] {result.message}")
    else:
        click.echo(f"[!] {result.message}")
        sys.exit(1)


@cli.command()
@click.option("--handshake", required=True, help="Ruta al archivo .cap capturado")
@click.option("--wordlist", required=True, help="Ruta al archivo de diccionario")
@click.option("--bssid", required=True, help="BSSID objetivo")
@click.option("--mock", is_flag=True, help="Usar datos simulados")
@click.pass_context
def crack(ctx: click.Context, handshake: str, wordlist: str, bssid: str, mock: bool) -> None:
    """Ataque de diccionario offline contra handshake capturado."""
    scope = ScopeManager.from_file(ctx.obj["scope_path"])
    logger = ctx.obj["logger"]

    # Verificar autorización antes de cualquier acción activa
    if not scope.is_authorized(bssid):
        logger.log_denied("DICTIONARY_ATTACK", bssid)
        click.echo(f"[!] DENEGADO: {bssid} no está en el alcance autorizado.")
        sys.exit(1)

    click.echo(f"[*] Descifrando handshake de {bssid}...")
    if mock:
        result = dictionary_attack_mock(bssid)
    else:
        result = dictionary_attack(
            handshake_path=handshake, wordlist_path=wordlist,
            bssid=bssid, scope=scope, logger=logger,
        )

    if result.success:
        click.echo(f"[+] CONTRASEÑA ENCONTRADA: {result.password_found}")
    else:
        click.echo(f"[!] {result.message}")


@cli.command()
@click.option("--scan-data", required=True, help="Ruta al JSON de resultados del escaneo")
@click.option("--output", default="report", help="Prefijo de salida (sin extensión)")
@click.option("--format", "fmt", type=click.Choice(["json", "html", "both"]), default="both")
@click.pass_context
def report(ctx: click.Context, scan_data: str, output: str, fmt: str) -> None:
    """Generar reporte de auditoría a partir de datos de escaneo."""
    with open(scan_data, encoding="utf-8") as fh:
        data = json.load(fh)

    # Cargar alcance si el archivo existe
    scope = ScopeManager.from_file(ctx.obj["scope_path"]) if Path(ctx.obj["scope_path"]).exists() else None

    report_obj = AuditReport()
    for net in data.get("networks", []):
        # Clasificar cifrado y calcular riesgo
        enc = classify_encryption(net.get("encryption", ""))
        factors = ScoringFactors(
            encryption=enc,
            wps_enabled=net.get("wps_enabled", False),
            default_creds_suspected=net.get("default_creds_suspected", False),
        )
        score, level = score_network(factors)

        # Mapear hallazgos a técnicas MITRE ATT&CK
        findings: list[str] = []
        if enc in ("WEP", "Open", "WPA"):
            findings.append("passive_sniffing" if enc == "Open" else "handshake_capture")
        if net.get("wps_enabled"):
            findings.append("wps_attack")
        if net.get("default_creds_suspected"):
            findings.append("default_credentials")

        report_obj.networks.append(
            NetworkReport(
                bssid=net["bssid"],
                ssid=net.get("ssid", ""),
                channel=net.get("channel", 0),
                encryption=enc,
                signal_strength=net.get("signal_strength", 0),
                wps_enabled=net.get("wps_enabled", False),
                default_creds_suspected=net.get("default_creds_suspected", False),
                vendor=net.get("vendor"),
                risk_score=score,
                risk_level=level,
                mitre_techniques=map_findings(findings),
                hardening_recommendations=build_hardening_recommendations(
                    enc, net.get("wps_enabled", False), net.get("default_creds_suspected", False)
                ),
                in_scope=scope.is_authorized(net["bssid"]) if scope else False,
            )
        )

    report_obj.build_summary()

    # Exportar en el formato solicitado
    if fmt in ("json", "both"):
        p = export_json(report_obj, f"{output}.json")
        click.echo(f"[+] Reporte JSON: {p}")
    if fmt in ("html", "both"):
        p = export_html(report_obj, f"{output}.html")
        click.echo(f"[+] Reporte HTML: {p}")


def main() -> None:
    """Punto de entrada principal del CLI."""
    cli(obj={})
