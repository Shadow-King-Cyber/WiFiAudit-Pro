"""Tests para el analizador de cifrado."""

import pytest
from wifiaudit_pro.analysis.encryption_analyzer import classify_encryption, encryption_summary


@pytest.mark.parametrize("input_str,expected", [
    ("WPA2", "WPA2"),
    ("WPA2-CCMP", "WPA2"),
    ("WPA3-SAE", "WPA3"),
    ("WPA", "WPA"),
    ("WPA-TKIP", "WPA"),
    ("WEP", "WEP"),
    ("OPN", "Open"),
    ("OPEN", "Open"),
    ("ESS", "Open"),
    ("wpa2", "WPA2"),
    ("WPA2/WPA3", "WPA3"),
])
def test_clasificar_cifrado(input_str, expected):
    """Verificar que la clasificación de cifrado funciona para todas las variantes."""
    assert classify_encryption(input_str) == expected


def test_resumen_wep():
    """El resumen de WEP debe mencionar que está roto."""
    s = encryption_summary("WEP")
    assert "roto" in s.lower() or "Broken" in s


def test_resumen_open():
    """El resumen de red abierta debe indicar sin cifrado."""
    s = encryption_summary("Open")
    assert "Sin cifrado" in s


def test_resumen_desconocido():
    """Cifrado desconocido debe devolver mensaje con 'desconocido'."""
    s = encryption_summary("XYZ")
    assert "desconocido" in s.lower() or "Unknown" in s
