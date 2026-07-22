import re
from dataclasses import dataclass, field

# Private / link-local ranges to exclude from IOC extraction
_PRIVATE_IP_PATTERNS = re.compile(
    r"^(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+|0\.0\.0\.0)$"
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# P2-PRE-03 (2026-07-20): domain TLD whitelist expanded with the common
# new-gTLD suffixes (.app / .dev / .ai / .me / .cloud / .sh / .tv etc).
# The previous list only covered the legacy gTLDs, which meant alerts
# referencing a `*.app` or `*.dev` domain dropped the IOC silently.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|cn|info|biz|co|gov|edu|ru|de|uk|fr|jp|kr|xyz|top|app|dev|ai|me|cloud|sh|tv|io\.cn|com\.cn|net\.cn|org\.cn|edu\.cn|gov\.cn|ac\.cn)\b"
)
_HASH_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_HASH_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_HASH_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]{4,}")


@dataclass
class IOCBundle:
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


class IOCExtractor:
    """Extract and deduplicate IOCs from sanitized text."""

    def extract(self, text: str) -> IOCBundle:
        bundle = IOCBundle()

        for m in _IP_RE.finditer(text):
            ip = m.group()
            if self._valid_ip(ip) and ip not in bundle.ips:
                bundle.ips.append(ip)

        for m in _DOMAIN_RE.finditer(text):
            domain = m.group().lower()
            if domain not in bundle.domains:
                bundle.domains.append(domain)

        seen_hashes: set[str] = set()
        for pattern in (_HASH_SHA256, _HASH_SHA1, _HASH_MD5):
            for m in pattern.finditer(text):
                h = m.group().lower()
                if h not in seen_hashes:
                    bundle.hashes.append(h)
                    seen_hashes.add(h)

        for m in _URL_RE.finditer(text):
            url = m.group()
            if url not in bundle.urls:
                bundle.urls.append(url)

        return bundle

    @staticmethod
    def _valid_ip(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            if not all(0 <= int(p) <= 255 for p in parts):
                return False
        except ValueError:
            return False
        return not bool(_PRIVATE_IP_PATTERNS.match(ip))
