"""Tests for IOCExtractor — IP, domain, hash, URL extraction."""
from src.preprocessing.ioc_extractor.extractor import IOCExtractor

extractor = IOCExtractor()


class TestIPExtraction:
    def test_public_ip(self):
        bundle = extractor.extract("Attack from 45.33.32.156")
        assert "45.33.32.156" in bundle.ips

    def test_private_ip_excluded(self):
        bundle = extractor.extract("Internal IP 192.168.1.1")
        assert "192.168.1.1" not in bundle.ips

    def test_localhost_excluded(self):
        bundle = extractor.extract("Localhost 127.0.0.1")
        assert "127.0.0.1" not in bundle.ips

    def test_multiple_ips(self):
        bundle = extractor.extract("IPs: 8.8.8.8, 10.0.0.1, 45.33.32.156")
        assert "8.8.8.8" in bundle.ips
        assert "10.0.0.1" not in bundle.ips
        assert "45.33.32.156" in bundle.ips

    def test_invalid_ip(self):
        bundle = extractor.extract("Invalid 999.999.999.999")
        assert bundle.ips == []

    def test_ip_deduplication(self):
        bundle = extractor.extract("Same IP 8.8.8.8 and 8.8.8.8 again")
        assert len(bundle.ips) == 1


class TestDomainExtraction:
    def test_basic_domain(self):
        bundle = extractor.extract("Visit malicious.com")
        assert "malicious.com" in bundle.domains

    def test_subdomain(self):
        bundle = extractor.extract("Sub evil.c2.example.com")
        assert "evil.c2.example.com" in bundle.domains

    def test_domain_deduplication(self):
        bundle = extractor.extract("malicious.com and MALICIOUS.com")
        assert len(bundle.domains) == 1
        assert bundle.domains[0] == "malicious.com"


class TestHashExtraction:
    def test_md5(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        bundle = extractor.extract(f"Hash {h}")
        assert h in bundle.hashes

    def test_sha1(self):
        h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        bundle = extractor.extract(f"SHA1 {h}")
        assert h in bundle.hashes

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        bundle = extractor.extract(f"SHA256 {h}")
        assert h in bundle.hashes

    def test_hash_deduplication_across_types(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        bundle = extractor.extract(f"{md5} {md5}")
        assert len(bundle.hashes) == 1


class TestURLExtraction:
    def test_http_url(self):
        bundle = extractor.extract("Download from http://evil.com/payload.exe")
        assert "http://evil.com/payload.exe" in bundle.urls

    def test_https_url(self):
        bundle = extractor.extract("Visit https://phishing.example.com/login")
        assert "https://phishing.example.com/login" in bundle.urls

    def test_url_deduplication(self):
        bundle = extractor.extract("http://evil.com http://evil.com")
        assert len(bundle.urls) == 1


class TestEmptyInput:
    def test_empty(self):
        bundle = extractor.extract("")
        assert len(bundle.ips) == 0
        assert len(bundle.domains) == 0
        assert len(bundle.hashes) == 0
        assert len(bundle.urls) == 0

    def test_no_iocs(self):
        bundle = extractor.extract("Just some text without IOCs here")
        assert len(bundle.ips) == 0
        assert len(bundle.domains) == 0

    def test_private_network_only(self):
        bundle = extractor.extract("Internal: 10.0.0.1, 172.16.0.1, 192.168.1.1")
        assert len(bundle.ips) == 0
