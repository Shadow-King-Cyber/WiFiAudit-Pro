"""Tests para el motor de scoring de riesgo."""

import pytest
from wifiaudit_pro.analysis.risk_scoring import (
    ScoringFactors,
    calculate_score,
    risk_level,
    score_network,
    SCORE_WEP,
    SCORE_OPEN,
    SCORE_WPA,
    SCORE_WPA2_PENALTY,
    SCORE_WPS_ENABLED,
    SCORE_DEFAULT_CREDS,
    SCORE_CHANNEL_OVERLAP,
)


class TestCalcularPuntaje:
    """Tests para la función calculate_score."""

    def test_wep_riesgo_alto(self):
        """WEP debe generar un puntaje alto (roto)."""
        f = ScoringFactors(encryption="WEP")
        assert calculate_score(f) == SCORE_WEP

    def test_open_riesgo_maximo(self):
        """Red abierta debe generar el puntaje más alto."""
        f = ScoringFactors(encryption="Open")
        assert calculate_score(f) == SCORE_OPEN

    def test_wpa_riesgo_moderado(self):
        """WPA debe generar un puntaje moderado."""
        f = ScoringFactors(encryption="WPA")
        assert calculate_score(f) == SCORE_WPA

    def test_wpa2_riesgo_bajo(self):
        """WPA2 debe generar un puntaje bajo."""
        f = ScoringFactors(encryption="WPA2")
        assert calculate_score(f) == SCORE_WPA2_PENALTY

    def test_wpa3_puntaje_cero(self):
        """WPA3 no debe generar puntaje (es seguro)."""
        f = ScoringFactors(encryption="WPA3")
        assert calculate_score(f) == 0

    def test_wps_suma_puntaje(self):
        """WPS habilitado debe sumar puntos al puntaje total."""
        f = ScoringFactors(encryption="WPA2", wps_enabled=True)
        assert calculate_score(f) == SCORE_WPA2_PENALTY + SCORE_WPS_ENABLED

    def test_credenciales_por_defecto_suma_puntaje(self):
        """Credenciales por defecto sospechadas deben sumar puntos."""
        f = ScoringFactors(encryption="WPA2", default_creds_suspected=True)
        assert calculate_score(f) == SCORE_WPA2_PENALTY + SCORE_DEFAULT_CREDS

    def test_solapamiento_canal_suma_puntaje(self):
        """Solapamiento severo de canal debe sumar puntos."""
        f = ScoringFactors(encryption="WPA2", channel_overlap_count=3)
        assert calculate_score(f) == SCORE_WPA2_PENALTY + SCORE_CHANNEL_OVERLAP

    def test_solapamiento_no_suma_con_una_red(self):
        """Con solo 1 red en el canal, no debe sumar puntos por solapamiento."""
        f = ScoringFactors(encryption="WPA2", channel_overlap_count=1)
        assert calculate_score(f) == SCORE_WPA2_PENALTY

    def test_todos_los_factores_combinados(self):
        """Verificar suma correcta con todos los factores activos."""
        f = ScoringFactors(
            encryption="WEP",
            wps_enabled=True,
            default_creds_suspected=True,
            channel_overlap_count=3,
        )
        expected = SCORE_WEP + SCORE_WPS_ENABLED + SCORE_DEFAULT_CREDS + SCORE_CHANNEL_OVERLAP
        assert calculate_score(f) == expected


class TestNivelRiesgo:
    """Tests para la función risk_level (mapeo de puntaje a nivel)."""

    @pytest.mark.parametrize("score,expected", [
        (0, "Bajo"),
        (15, "Bajo"),
        (16, "Medio"),
        (35, "Medio"),
        (36, "Alto"),
        (60, "Alto"),
        (61, "Critico"),
        (100, "Critico"),
    ])
    def test_limites(self, score, expected):
        """Verificar que los límites de cada nivel son correctos."""
        assert risk_level(score) == expected


class TestScoreNetwork:
    """Tests para la función score_network (scoring completo)."""

    def test_devuelve_tupla(self):
        """score_network debe devolver una tupla (int, str)."""
        f = ScoringFactors(encryption="WPA2")
        s, l = score_network(f)
        assert isinstance(s, int)
        assert isinstance(l, str)

    def test_wpa2_nivel_bajo(self):
        """WPA2 sin extras debe tener nivel Bajo."""
        f = ScoringFactors(encryption="WPA2")
        s, l = score_network(f)
        assert s == SCORE_WPA2_PENALTY
        assert l == "Bajo"

    def test_open_con_extras_nivel_critico(self):
        """Red abierta con WPS + credenciales por defecto + solapamiento = Crítico."""
        f = ScoringFactors(
            encryption="Open",
            wps_enabled=True,
            default_creds_suspected=True,
            channel_overlap_count=3,
        )
        s, l = score_network(f)
        assert s >= 61
        assert l == "Critico"
