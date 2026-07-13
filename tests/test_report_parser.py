"""Tests para el constructor de reportes y exportadores."""

import json
import tempfile
from pathlib import Path

import pytest
from wifiaudit_pro.reporting.report_builder import (
    AuditReport,
    NetworkReport,
    build_hardening_recommendations,
)
from wifiaudit_pro.reporting.json_exporter import export_json


@pytest.fixture
def sample_report():
    """Fixture que crea un reporte de ejemplo con dos redes de prueba."""
    report = AuditReport()
    report.networks = [
        NetworkReport(
            bssid="AA:BB:CC:DD:EE:01",
            ssid="RedWEP",
            channel=1,
            encryption="WEP",
            signal_strength=-45,
            wps_enabled=True,
            default_creds_suspected=True,
            vendor="TP-Link",
            risk_score=95,
            risk_level="Critico",
            mitre_techniques=[],
            hardening_recommendations=[],
            in_scope=True,
        ),
        NetworkReport(
            bssid="AA:BB:CC:DD:EE:02",
            ssid="RedWPA3",
            channel=6,
            encryption="WPA3",
            signal_strength=-55,
            wps_enabled=False,
            default_creds_suspected=False,
            vendor=None,
            risk_score=0,
            risk_level="Bajo",
            mitre_techniques=[],
            hardening_recommendations=[],
            in_scope=False,
        ),
    ]
    report.build_summary()
    return report


def test_resumen_total_redes(sample_report):
    """Verificar que el total de redes es correcto."""
    assert sample_report.summary["total_networks"] == 2


def test_resumen_distribucion_cifrado(sample_report):
    """Verificar la distribución por tipo de cifrado."""
    dist = sample_report.summary["encryption_distribution"]
    assert dist.get("WEP") == 1
    assert dist.get("WPA3") == 1


def test_resumen_distribucion_riesgo(sample_report):
    """Verificar la distribución por nivel de riesgo."""
    dist = sample_report.summary["risk_distribution"]
    assert dist.get("Critico") == 1
    assert dist.get("Bajo") == 1


def test_resumen_conteo_wps(sample_report):
    """Verificar el conteo de redes con WPS habilitado."""
    assert sample_report.summary["wps_enabled_count"] == 1


def test_resumen_conteo_credenciales(sample_report):
    """Verificar el conteo de redes con credenciales por defecto."""
    assert sample_report.summary["default_creds_count"] == 1


def test_resumen_conteo_en_alcance(sample_report):
    """Verificar el conteo de redes dentro del alcance."""
    assert sample_report.summary["in_scope_count"] == 1


class TestRecomendacionesHardening:
    """Tests para las recomendaciones de endurecimiento."""

    def test_wep_indica_urgencia(self):
        """WEP debe generar recomendaciones con urgencia."""
        recs = build_hardening_recommendations("WEP", False, False)
        assert any("URGENTE" in r for r in recs)

    def test_red_abierta(self):
        """Red abierta debe generar recomendaciones críticas."""
        recs = build_hardening_recommendations("Open", False, False)
        assert any("CRÍTICO" in r for r in recs)

    def test_recomendacion_wps(self):
        """WPS habilitado debe generar recomendación para deshabilitarlo."""
        recs = build_hardening_recommendations("WPA2", True, False)
        assert any("WPS" in r for r in recs)

    def test_recomendacion_credenciales(self):
        """Credenciales por defecto deben generar recomendación para cambiarlas."""
        recs = build_hardening_recommendations("WPA2", False, True)
        assert any("por defecto" in r.lower() for r in recs)

    def test_wpa3_minimo(self):
        """WPA3 debe generar al menos una recomendación."""
        recs = build_hardening_recommendations("WPA3", False, False)
        assert len(recs) >= 1


class TestExportadorJson:
    """Tests para el exportador JSON."""

    def test_exportar_crea_archivo(self, sample_report, tmp_path):
        """Verificar que el archivo JSON se crea correctamente."""
        out = tmp_path / "reporte_prueba.json"
        result = export_json(sample_report, out)
        assert result.exists()

    def test_exportar_json_valido(self, sample_report, tmp_path):
        """Verificar que el JSON generado es válido y tiene la estructura correcta."""
        out = tmp_path / "reporte_prueba.json"
        export_json(sample_report, out)
        with open(out) as fh:
            data = json.load(fh)
        assert data["title"] == "WiFiAudit-Pro Security Report"
        assert len(data["networks"]) == 2

    def test_exportar_crea_directorios(self, sample_report, tmp_path):
        """Verificar que se crean los directorios padre si no existen."""
        out = tmp_path / "subdirectorio" / "reporte.json"
        export_json(sample_report, out)
        assert out.exists()
