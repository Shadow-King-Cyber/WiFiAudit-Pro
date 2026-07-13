"""Tests para el módulo de mapeo MITRE ATT&CK."""

from wifiaudit_pro.mitre import get_technique, map_findings


def test_obtener_tecnica_conocida():
    """Verificar que se obtiene la técnica MITRE para un hallazgo conocido."""
    t = get_technique("passive_sniffing")
    assert t is not None
    assert t["id"] == "T1040"


def test_obtener_tecnica_desconocida():
    """Verificar que se devuelve None para un hallazgo inexistente."""
    assert get_technique("inexistente") is None


def test_mapear_hallazgos_deduplicados():
    """Verificar que hallazgos que mapean a la misma técnica se deduplican."""
    results = map_findings(["passive_sniffing", "handshake_capture", "open_network"])
    ids = [r["id"] for r in results]
    # Los tres mapean a T1040, debe aparecer solo una vez
    assert ids.count("T1040") == 1


def test_mapear_hallazgos_multiples():
    """Verificar que se mapean múltiples técnicas diferentes."""
    results = map_findings(["passive_sniffing", "dictionary_attack"])
    ids = {r["id"] for r in results}
    assert "T1040" in ids
    assert "T1110.002" in ids
