"""Base de datos de credenciales por defecto — valores de fábrica conocidos por fabricante/modelo."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DefaultCredential:
    """Representa una credencial por defecto conocida de un fabricante."""
    vendor: str                 # Fabricante (ej. "TP-Link", "Netgear")
    model_pattern: str          # Patrón de modelo para coincidencia simple (ej. "TL-WR", "RT-")
    default_ssid_prefix: str    # Prefijo SSID por defecto común (ej. "TP-LINK_")
    username: str               # Usuario por defecto
    password: str               # Contraseña por defecto (puede estar vacía)
    note: str = ""              # Nota adicional


# Lista curada — pequeña pero práctica; evita dependencias de BD externas.
# Cada entrada documenta credenciales de fábrica conocidas para routers comunes.
DEFAULT_CREDENTIALS_DB: list[DefaultCredential] = [
    DefaultCredential(
        vendor="TP-Link",
        model_pattern="TL-WR",
        default_ssid_prefix="TP-LINK_",
        username="admin",
        password="admin",
        note="Router doméstico muy común; el SSID revela el fabricante.",
    ),
    DefaultCredential(
        vendor="TP-Link",
        model_pattern="Archer",
        default_ssid_prefix="TP-Link_",
        username="admin",
        password="admin",
    ),
    DefaultCredential(
        vendor="Netgear",
        model_pattern="WNR",
        default_ssid_prefix="NETGEAR",
        username="admin",
        password="password",
    ),
    DefaultCredential(
        vendor="Netgear",
        model_pattern="R",
        default_ssid_prefix="NETGEAR",
        username="admin",
        password="password",
    ),
    DefaultCredential(
        vendor="Linksys",
        model_pattern="WRT",
        default_ssid_prefix="Linksys",
        username="admin",
        password="admin",
    ),
    DefaultCredential(
        vendor="D-Link",
        model_pattern="DIR",
        default_ssid_prefix="dlink",
        username="admin",
        password="",
        note="Contraseña por defecto vacía.",
    ),
    DefaultCredential(
        vendor="Huawei",
        model_pattern="HG",
        default_ssid_prefix="HUAWEI",
        username="admin",
        password="admin",
    ),
    DefaultCredential(
        vendor="ZTE",
        model_pattern="ZXHN",
        default_ssid_prefix="ZTE-",
        username="admin",
        password="admin",
    ),
    DefaultCredential(
        vendor="ASUS",
        model_pattern="RT-",
        default_ssid_prefix="ASUS",
        username="admin",
        password="admin",
    ),
    DefaultCredential(
        vendor="MikroTik",
        model_pattern="RB",
        default_ssid_prefix="MikroTik",
        username="admin",
        password="",
        note="Contraseña por defecto vacía; debe configurarse en el primer inicio.",
    ),
]


def check_default_creds(ssid: str, vendor: str | None = None) -> bool:
    """Devuelve ``True`` si el SSID (y fabricante opcional) coincide con un patrón de credenciales por defecto conocido."""
    ssid_upper = ssid.upper()
    for entry in DEFAULT_CREDENTIALS_DB:
        # Verificar si el SSID comienza con el prefijo por defecto del fabricante
        if ssid_upper.startswith(entry.default_ssid_prefix.upper()):
            return True
        # Si se proporciona fabricante, verificar coincidencia directa
        if vendor and vendor.lower() == entry.vendor.lower():
            return True
    return False


def get_default_creds(ssid: str, vendor: str | None = None) -> DefaultCredential | None:
    """Devuelve la entrada ``DefaultCredential`` que coincide, o ``None``."""
    ssid_upper = ssid.upper()
    for entry in DEFAULT_CREDENTIALS_DB:
        if ssid_upper.startswith(entry.default_ssid_prefix.upper()):
            return entry
        if vendor and vendor.lower() == entry.vendor.lower():
            return entry
    return None
