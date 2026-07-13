"""Tests para la base de datos de credenciales por defecto."""

from wifiaudit_pro.analysis.default_creds_db import check_default_creds, get_default_creds


def test_tplink_detectado():
    """Verificar que TP-Link con SSID por defecto es detectado."""
    assert check_default_creds("TP-LINK_WR841N") is True


def test_netgear_detectado():
    """Verificar que Netgear con SSID por defecto es detectado."""
    assert check_default_creds("NETGEAR_WNR2000") is True


def test_ssid_desconocido():
    """Verificar que un SSID personalizado no es detectado como credencial por defecto."""
    assert check_default_creds("MiRedPersonalizada123") is False


def test_obtener_credenciales_encontradas():
    """Verificar que se obtienen las credenciales correctas para TP-Link."""
    creds = get_default_creds("TP-LINK_WR841N")
    assert creds is not None
    assert creds.vendor == "TP-Link"


def test_obtener_credenciales_no_encontradas():
    """Verificar que se devuelve None para SSIDs sin coincidencia."""
    assert get_default_creds("RedPersonalizada") is None
