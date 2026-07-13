"""Tests para el logger de auditoría."""

import json
from pathlib import Path

from wifiaudit_pro.core.audit_logger import AuditLogger


def test_log_crea_registro(tmp_path):
    """Verificar que log crea un registro con los campos correctos."""
    log_path = tmp_path / "test_log.jsonl"
    logger = AuditLogger(str(log_path))
    record = logger.log("SCAN", "AA:BB:CC:DD:EE:01", "SUCCESS")

    assert record["action"] == "SCAN"
    assert record["bssid"] == "AA:BB:CC:DD:EE:01"
    assert record["result"] == "SUCCESS"
    assert "timestamp" in record
    assert "user" in record


def test_log_denegado(tmp_path):
    """Verificar que log_denied registra correctamente una acción denegada."""
    log_path = tmp_path / "test_log.jsonl"
    logger = AuditLogger(str(log_path))
    record = logger.log_denied("HANDSHAKE_CAPTURE", "FF:FF:FF:FF:FF:FF")
    assert record["result"] == "DENIED_NOT_IN_SCOPE"


def test_leer_todos(tmp_path):
    """Verificar que read_all devuelve todos los registros escritos."""
    log_path = tmp_path / "test_log.jsonl"
    logger = AuditLogger(str(log_path))
    logger.log("SCAN", "AA:BB:CC:DD:EE:01", "SUCCESS")
    logger.log("CRACK", "AA:BB:CC:DD:EE:01", "NOT_FOUND")

    records = logger.read_all()
    assert len(records) == 2


def test_solo_append(tmp_path):
    """Verificar que el log solo permite agregar registros (append-only)."""
    log_path = tmp_path / "test_log.jsonl"
    logger = AuditLogger(str(log_path))
    logger.log("ACTION1", "AA:BB:CC:DD:EE:01", "OK")
    logger.log("ACTION2", "AA:BB:CC:DD:EE:01", "OK")

    records = logger.read_all()
    # Verificar el orden de los registros
    assert records[0]["action"] == "ACTION1"
    assert records[1]["action"] == "ACTION2"
