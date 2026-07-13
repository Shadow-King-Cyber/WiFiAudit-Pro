"""Tests para el módulo de ataque (verificación de alcance)."""

import json
import tempfile
from pathlib import Path

import pytest
from wifiaudit_pro.core.scope_manager import ScopeManager
from wifiaudit_pro.core.audit_logger import AuditLogger
from wifiaudit_pro.attack import dictionary_attack_mock, CrackResult


@pytest.fixture
def scope_and_logger(tmp_path):
    """Fixture que crea un ScopeManager y AuditLogger para pruebas."""
    scope_data = {
        "networks": [{"bssid": "AA:BB:CC:DD:EE:01", "ssid": "RedPrueba"}],
    }
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps(scope_data))
    scope = ScopeManager.from_file(scope_path)
    logger = AuditLogger(str(tmp_path / "log.jsonl"))
    return scope, logger


def test_ataque_simulado_exito():
    """Verificar que el ataque simulado indica éxito."""
    result = dictionary_attack_mock("AA:BB:CC:DD:EE:01")
    assert result.success is True
    assert result.password_found is not None


def test_puerta_de_alcance_rechaza_no_autorizado(tmp_path, scope_and_logger):
    """Verificar que el BSSID no autorizado es rechazado por la puerta de alcance."""
    scope, logger = scope_and_logger
    from wifiaudit_pro.attack import dictionary_attack

    result = dictionary_attack(
        handshake_path="fake.cap",
        wordlist_path="fake.txt",
        bssid="FF:FF:FF:FF:FF:FF",  # BSSID fuera del alcance
        scope=scope,
        logger=logger,
    )
    assert result.success is False
    assert "NO está en el alcance autorizado" in result.message
