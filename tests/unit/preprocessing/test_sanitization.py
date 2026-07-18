from src.preprocessing.sanitization.engine import SanitizationEngine

engine = SanitizationEngine()


class TestPasswordMasking:
    def test_equals_format(self):
        result = engine.sanitize("password=s3cr3t123")
        assert "s3cr3t123" not in result
        assert "password=***" in result

    def test_colon_format(self):
        result = engine.sanitize("passwd: myP@ssword!")
        assert "myP@ssword!" not in result

    def test_case_insensitive(self):
        result = engine.sanitize("PASSWORD=abc123")
        assert "abc123" not in result

    def test_api_key(self):
        result = engine.sanitize("api_key=sk-ant-abc1234567890")
        assert "sk-ant" not in result


class TestPhoneMasking:
    def test_cn_mobile(self):
        result = engine.sanitize("用户手机号: 13812345678")
        assert "13812345678" not in result
        assert "138" in result
        assert "5678" in result

    def test_non_phone_preserved(self):
        result = engine.sanitize("port 13812")
        # 5-digit numbers should not be masked
        assert "13812" in result

    def test_multiple_phones(self):
        text = "contact: 13800138000 or 15912345678"
        result = engine.sanitize(text)
        assert "13800138000" not in result
        assert "15912345678" not in result


class TestEmailMasking:
    def test_basic_email(self):
        result = engine.sanitize("email: admin@example.com")
        assert "admin@example.com" not in result
        assert "@example.com" in result

    def test_email_in_sentence(self):
        result = engine.sanitize("Send report to john.doe@company.org today")
        assert "john.doe" not in result


class TestNoFalsePositives:
    def test_normal_log_preserved(self):
        text = "User logged in from 203.0.113.5 at 2026-01-01T00:00:00Z"
        result = engine.sanitize(text)
        assert "203.0.113.5" in result
        assert "2026-01-01" in result

    def test_plain_text_preserved(self):
        text = "System health check passed. All services operational."
        assert engine.sanitize(text) == text
