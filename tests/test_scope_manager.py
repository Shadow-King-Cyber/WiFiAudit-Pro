"""Tests para ScopeManager (Gestor de Alcance)."""

import json
import tempfile
from pathlib import Path

import pytest
from wifiaudit_pro.core.scope_manager import ScopeManager


@pytest.fixture
def scope_file(tmp_path):
    """Fixture que crea un archivo de alcance temporal con redes de prueba."""
    data = {
        "authorized_by": "Administrador de Pruebas",
        "authorization_date": "2026-01-01",
        "networks": [
            {"bssid": "AA:BB:CC:DD:EE:01", "ssid": "RedPrueba1", "note": "Laboratorio"},
            {"bssid": "AA:BB:CC:DD:EE:02", "ssid": "RedPrueba2", "note": "Oficina"},
        ],
    }
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(data))
    return path


def test_cargar_alcance(scope_file):
    """Verifica que el archivo de alcance se carga correctamente."""
    sm = ScopeManager.from_file(scope_file)
    assert len(sm.networks) == 2
    assert sm.authorized_by == "Administrador de Pruebas"


def test_bssid_autorizado(scope_file):
    """Verifica que un BSSID autorizado es reconocido (case-insensitive)."""
    sm = ScopeManager.from_file(scope_file)
    assert sm.is_authorized("AA:BB:CC:DD:EE:01") is True
    assert sm.is_authorized("aa:bb:cc:dd:ee:01") is True  # sin distinción de mayúsculas


def test_bssid_no_autorizado(scope_file):
    """Verifica que un BSSID no autorizado es rechazado."""
    sm = ScopeManager.from_file(scope_file)
    assert sm.is_authorized("FF:FF:FF:FF:FF:FF") is False


def test_obtener_entrada(scope_file):
    """Verifica que se puede obtener la entrada completa de un BSSID."""
    sm = ScopeManager.from_file(scope_file)
    entry = sm.get_entry("AA:BB:CC:DD:EE:01")
    assert entry is not None
    assert entry.ssid == "RedPrueba1"


def test_entrada_no_encontrada(scope_file):
    """Verifica que get_entry devuelve None para BSSIDs inexistentes."""
    sm = ScopeManager.from_file(scope_file)
    assert sm.get_entry("FF:FF:FF:FF:FF:FF") is None


def test_propiedad_bssids(scope_file):
    """Verifica que la propiedad bssids devuelve el conjunto correcto."""
    sm = ScopeManager.from_file(scope_file)
    assert sm.bssids == {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}


def test_archivo_no_encontrado():
    """Verifica que se lanza FileNotFoundError para rutas inexistentes."""
    with pytest.raises(FileNotFoundError):
        ScopeManager.from_file("/ruta/no/existente/scope.json")


def test_redes_vacias(tmp_path):
    """Verifica el comportamiento con un archivo de alcance sin redes."""
    path = tmp_path / "vacio.json"
    path.write_text(json.dumps({"networks": []}))
    sm = ScopeManager.from_file(path)
    assert len(sm.networks) == 0
    # Sin redes, ningún BSSID está autorizado
    assert sm.is_authorized("AA:BB:CC:DD:EE:01") is False
