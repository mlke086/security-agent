"""Unit tests for asset-scan scanner pure logic (需求②)."""

from src.asset_scan.scanner.version import (
    compare_versions,
    normalize_cpe_version,
    version_matches,
)


class TestVersionCompare:
    def test_simple_ordering(self):
        assert compare_versions("1.18.0", "1.18.1") < 0
        assert compare_versions("1.18.1", "1.18.0") > 0
        assert compare_versions("1.18.0", "1.18.0") == 0

    def test_rc_sorts_after_release(self):
        # dpkg/Go 端语义：revision 非空 > 空（"1.18.0-rc1" > "1.18.0"）。
        # 预发布要用 '~'（1.18.0~rc1 < 1.18.0）。与 matcher.go 保持一致。
        assert compare_versions("1.18.0-rc1", "1.18.0") > 0
        assert compare_versions("1.18.0", "1.18.0-rc1") < 0
        assert compare_versions("1.18.0~rc1", "1.18.0") < 0

    def test_epoch_wins(self):
        assert compare_versions("1:0.1", "0.9") > 0
        assert compare_versions("0.9", "1:0.1") < 0

    def test_revision(self):
        assert compare_versions("1.2.3-1", "1.2.3-2") < 0
        assert compare_versions("1.2.3-2.el9", "1.2.3-10.el9") < 0  # 数字段数值比较
        assert compare_versions("1.2.3", "1.2.3-1") < 0  # 空 revision < 非空

    def test_tilde_sorts_before_everything(self):
        assert compare_versions("1.0~beta1", "1.0") < 0
        # '~' 之后按 ASCII：beta < rc
        assert compare_versions("1.0~beta2", "1.0~rc1") < 0
        assert compare_versions("1.0~rc1", "1.0~beta2") > 0

    def test_padded_zeros(self):
        assert compare_versions("1.2.03", "1.2.3") == 0
        assert compare_versions("1.2.3", "1.2.003") == 0

    def test_empty_and_missing_parts(self):
        assert compare_versions("1.2.3", "1.2") > 0
        assert compare_versions("", "0") == 0


class TestVersionMatches:
    def test_lt_le_gt(self):
        assert version_matches("1.2.0", "lt", "1.3.0")
        assert not version_matches("1.3.0", "lt", "1.3.0")
        assert version_matches("1.3.0", "le", "1.3.0")
        assert version_matches("1.4.0", "gt", "1.3.0")
        assert version_matches("1.3.0", "ge", "1.3.0")

    def test_english_ops(self):
        assert version_matches("1.2.0", "lt", "1.3.0")
        assert version_matches("1.3.0", "eq", "1.3.0")
        assert version_matches("1.4.0", "gt", "1.3.0")


class TestNormalizeCpeVersion:
    def test_underscore_is_revision(self):
        assert normalize_cpe_version("1.2.3_1") == "1.2.3-1"

    def test_wildcard_empty(self):
        assert normalize_cpe_version("*") == ""
        assert normalize_cpe_version("") == ""
        assert normalize_cpe_version("-") == "-"  # 原样


class TestRuleProductMatch:
    def test_exact_and_prefixed(self):
        from src.asset_scan.scanner.vuln_match import _rule_product_matches

        assert _rule_product_matches("nginx", "nginx")
        assert _rule_product_matches("nginx", "nginx/1.18.0")
        assert _rule_product_matches("nginx", "nginx 1.18.0")
        assert _rule_product_matches("nginx", "nginx-1.18.0")
        assert not _rule_product_matches("nginx", "apache")
        assert not _rule_product_matches("", "nginx")
