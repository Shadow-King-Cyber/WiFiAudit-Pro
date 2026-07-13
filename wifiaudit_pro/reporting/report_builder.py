"""Constructor de reportes — construye el modelo de datos canónico del reporte."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class NetworkReport:
    """Datos del reporte para una red individual."""
    bssid: str
    ssid: str
    channel: int
    encryption: str
    signal_strength: int
    wps_enabled: bool
    default_creds_suspected: bool
    vendor: str | None
    risk_score: int
    risk_level: str
    mitre_techniques: list[dict[str, str]]
    hardening_recommendations: list[str]
    in_scope: bool


@dataclass
class AuditReport:
    """Reporte completo de auditoría con todas las redes analizadas."""
    title: str = "WiFiAudit-Pro Security Report"
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    networks: list[NetworkReport] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def build_summary(self) -> None:
        """Calcula estadísticas agregadas a partir de la lista de redes."""
        total = len(self.networks)

        # Distribución por tipo de cifrado
        encryption_dist: dict[str, int] = {}
        # Distribución por nivel de riesgo
        risk_dist: dict[str, int] = {"Critico": 0, "Alto": 0, "Medio": 0, "Bajo": 0}

        for net in self.networks:
            encryption_dist[net.encryption] = encryption_dist.get(net.encryption, 0) + 1
            risk_dist[net.risk_level] = risk_dist.get(net.risk_level, 0) + 1

        # Construir resumen con todas las métricas
        self.summary = {
            "total_networks": total,
            "encryption_distribution": encryption_dist,
            "risk_distribution": risk_dist,
            "wps_enabled_count": sum(1 for n in self.networks if n.wps_enabled),
            "default_creds_count": sum(1 for n in self.networks if n.default_creds_suspected),
            "in_scope_count": sum(1 for n in self.networks if n.in_scope),
        }


def build_hardening_recommendations(
    encryption: str,
    wps_enabled: bool,
    default_creds: bool,
) -> list[str]:
    """Genera recomendaciones de hardening basadas en los hallazgos."""
    recs: list[str] = []

    # Mapa de recomendaciones por tipo de cifrado
    recs_map = {
        "WEP": [
            "URGENTE: WEP está roto. Actualizar a WPA3 o WPA2-AES inmediatamente.",
            "Reemplazar todas las claves WPA3-Personal o WPA2-AES.",
        ],
        "WPA": [
            "WPA con TKIP está obsoleto. Actualizar a WPA2-AES o WPA3.",
            "Deshabilitar cifrado TKIP en la configuración del router.",
        ],
        "WPA2": [
            "Asegurar que WPA2 use AES (CCMP), no TKIP.",
            "Considerar actualización a WPA3 para autenticación SAE.",
            "Habilitar 802.11w (Protección de Tramas de Gestión) si es compatible.",
        ],
        "WPA3": [
            "WPA3 es la mejor práctica actual. Asegurar que el modo de transición esté deshabilitado.",
            "Monitorear vulnerabilidades Dragonblood y mantener firmware actualizado.",
        ],
        "Open": [
            "CRÍTICO: La red no tiene cifrado. Todo el tráfico está en texto plano.",
            "Implementar WPA3-Personal o WPA2-AES como mínimo.",
            "Si es abierta por diseño (red de invitados), aislar de recursos internos.",
        ],
    }

    recs.extend(recs_map.get(encryption, []))

    # Recomendaciones adicionales por hallazgos específicos
    if wps_enabled:
        recs.append("Deshabilitar WPS (Wi-Fi Protected Setup) — vulnerable a fuerza bruta y Pixie Dust.")
        recs.append("Si WPS es requerido, usar WPS 2.0 con PIN no predeterminado.")

    if default_creds:
        recs.append("Cambiar credenciales por defecto inmediatamente. Los valores de fábrica son públicamente conocidos.")
        recs.append("Usar contraseña fuerte y única (16+ caracteres, mayúsculas, minúsculas, números, símbolos).")

    return recs
