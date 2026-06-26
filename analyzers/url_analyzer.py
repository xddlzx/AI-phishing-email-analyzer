from typing import Dict, Any, List, Union, Optional
from urllib.parse import urlparse
import re
import ipaddress


class PhishingURLAnalyzer:
    """
    URL analysis module for the AI-Powered Phishing Email Analyzer.

    This module performs static defensive analysis only.
    It extracts and analyzes URLs without opening, visiting, expanding,
    or interacting with them.
    """

    MAX_SCORE = 20

    URL_PATTERN = re.compile(
        r"(?i)\b(?:https?://|www\.)[^\s<>\"]+"
    )

    SHORTENED_DOMAINS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "cutt.ly",
        "rebrand.ly",
        "shorturl.at",
        "rb.gy",
        "s.id",
        "lnkd.in",
        "bitly.com",
    }

    SUSPICIOUS_TLDS = {
        "zip",
        "mov",
        "top",
        "xyz",
        "click",
        "work",
        "support",
        "cam",
        "country",
        "stream",
        "gq",
        "tk",
        "ml",
        "cf",
        "ga",
        "ru",
    }

    SENSITIVE_KEYWORDS = {
        "login",
        "verify",
        "verification",
        "account",
        "password",
        "reset",
        "secure",
        "security",
        "update",
        "billing",
        "payment",
        "invoice",
        "wallet",
        "bank",
        "confirm",
        "signin",
        "sign-in",
        "mfa",
        "2fa",
        "unlock",
        "suspend",
        "suspended",
    }

    BRAND_DOMAINS = {
        "microsoft": ["microsoft.com", "office.com", "office365.com", "outlook.com"],
        "google": ["google.com", "gmail.com"],
        "paypal": ["paypal.com"],
        "apple": ["apple.com"],
        "amazon": ["amazon.com"],
        "github": ["github.com"],
        "linkedin": ["linkedin.com"],
        "dropbox": ["dropbox.com"],
        "dhl": ["dhl.com"],
        "fedex": ["fedex.com"],
        "netflix": ["netflix.com"],
        "instagram": ["instagram.com"],
        "facebook": ["facebook.com", "meta.com"],
    }

    def analyze(self, input_data: Union[str, List[str]]) -> Dict[str, Any]:
        """
        Analyze URLs from email body or a provided URL list.

        Args:
            input_data:
                - email body text containing URLs, or
                - list of URL strings

        Returns:
            Dictionary containing module score, classification,
            analyzed URLs, and explanation-ready findings.
        """

        urls = self._get_urls(input_data)

        findings: List[Dict[str, Any]] = []
        analyzed_urls: List[Dict[str, Any]] = []
        score = 0

        if not urls:
            return {
                "module": "url_analysis",
                "score": 0,
                "max_score": self.MAX_SCORE,
                "classification": "NO_URLS_FOUND",
                "urls_found": [],
                "findings": []
            }

        for url in urls:
            url_result = self._analyze_single_url(url)
            analyzed_urls.append(url_result)

            for finding in url_result["findings"]:
                findings.append(finding)
                score += finding["score"]

        final_score = min(score, self.MAX_SCORE)

        return {
            "module": "url_analysis",
            "score": final_score,
            "max_score": self.MAX_SCORE,
            "classification": self._classify_score(final_score),
            "urls_found": analyzed_urls,
            "findings": findings
        }

    def _get_urls(self, input_data: Union[str, List[str]]) -> List[str]:
        if isinstance(input_data, list):
            return list(dict.fromkeys([self._clean_url(url) for url in input_data if url]))

        if isinstance(input_data, str):
            urls = self.URL_PATTERN.findall(input_data)
            cleaned_urls = [self._clean_url(url) for url in urls]
            return list(dict.fromkeys([url for url in cleaned_urls if url]))

        raise TypeError("input_data must be an email text string or a list of URLs.")

    def _clean_url(self, url: str) -> str:
        """
        Remove common trailing punctuation from extracted URLs.
        """

        return url.strip().strip(".,;!?)\"]}'")

    def _analyze_single_url(self, original_url: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []

        normalized_url = self._normalize_url(original_url)
        parsed = urlparse(normalized_url)

        hostname = parsed.hostname.lower() if parsed.hostname else None
        base_domain = self._base_domain(hostname) if hostname else None
        tld = self._extract_tld(hostname) if hostname else None

        if not hostname:
            self._add_finding(
                findings,
                severity="Medium",
                score=4,
                finding="URL hostname could not be parsed.",
                explanation=f"The URL '{original_url}' could not be parsed correctly.",
                url=original_url
            )

            return {
                "url": original_url,
                "normalized_url": normalized_url,
                "hostname": None,
                "base_domain": None,
                "tld": None,
                "findings": findings
            }

        # 1. IP address as URL host
        if self._is_ip_address(hostname):
            self._add_finding(
                findings,
                severity="High",
                score=8,
                finding="URL uses an IP address instead of a domain name.",
                explanation=(
                    f"The URL host '{hostname}' is an IP address. "
                    f"Phishing links sometimes use raw IP addresses to hide identity."
                ),
                url=original_url
            )

        # 2. @ symbol trick
        if parsed.username is not None:
            self._add_finding(
                findings,
                severity="High",
                score=8,
                finding="URL contains '@' symbol before the real hostname.",
                explanation=(
                    "URLs like 'trusted.com@evil.com' can mislead users. "
                    f"The actual hostname is '{hostname}'."
                ),
                url=original_url
            )

        # 3. Punycode / IDN
        if "xn--" in hostname:
            decoded_hostname = self._decode_punycode(hostname)
            self._add_finding(
                findings,
                severity="High",
                score=7,
                finding="URL contains punycode / internationalized domain encoding.",
                explanation=(
                    f"The hostname '{hostname}' decodes to '{decoded_hostname}'. "
                    f"This may indicate a homograph or lookalike-domain technique."
                ),
                url=original_url
            )

        # 4. Shortened URL
        if base_domain in self.SHORTENED_DOMAINS:
            self._add_finding(
                findings,
                severity="Medium",
                score=5,
                finding="URL uses a known URL shortening service.",
                explanation=(
                    f"The domain '{base_domain}' is a URL shortener. "
                    f"Shortened links can hide the final destination."
                ),
                url=original_url
            )

        # 5. Too many subdomains
        subdomain_count = self._count_subdomains(hostname)

        if subdomain_count >= 3:
            self._add_finding(
                findings,
                severity="Medium",
                score=5,
                finding="URL contains many subdomains.",
                explanation=(
                    f"The hostname '{hostname}' has {subdomain_count} subdomain levels. "
                    f"Phishing URLs may use long subdomain chains to hide the real domain."
                ),
                url=original_url
            )

        # 6. Suspicious TLD
        if tld in self.SUSPICIOUS_TLDS:
            self._add_finding(
                findings,
                severity="Low",
                score=3,
                finding="URL uses a suspicious or commonly abused TLD.",
                explanation=(
                    f"The URL uses the '.{tld}' top-level domain. "
                    f"This does not prove phishing, but it can increase suspicion."
                ),
                url=original_url
            )

        # 7. HTTP instead of HTTPS
        if parsed.scheme.lower() == "http":
            self._add_finding(
                findings,
                severity="Low",
                score=2,
                finding="URL uses HTTP instead of HTTPS.",
                explanation=(
                    "The URL is not using HTTPS. This is a weak signal by itself, "
                    "but it is suspicious when combined with login or account-related content."
                ),
                url=original_url
            )

        # 8. Suspicious path/query keywords
        score_added = self._analyze_sensitive_keywords(
            findings=findings,
            parsed_url=parsed,
            original_url=original_url
        )

        # 9. Brand impersonation and domain similarity
        if base_domain:
            self._analyze_brand_impersonation(
                findings=findings,
                hostname=hostname,
                base_domain=base_domain,
                original_url=original_url
            )

        return {
            "url": original_url,
            "normalized_url": normalized_url,
            "hostname": hostname,
            "base_domain": base_domain,
            "tld": tld,
            "subdomain_count": subdomain_count,
            "findings": findings
        }

    def _normalize_url(self, url: str) -> str:
        """
        Add scheme to URLs starting with www. so urlparse can parse them.
        """

        if url.lower().startswith("www."):
            return "http://" + url

        return url

    def _is_ip_address(self, hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    def _extract_tld(self, hostname: Optional[str]) -> Optional[str]:
        if not hostname or "." not in hostname:
            return None

        return hostname.split(".")[-1].lower()

    def _base_domain(self, hostname: Optional[str]) -> Optional[str]:
        """
        Simple base-domain extraction.

        Example:
            login.security.example.com -> example.com

        Good enough for version 1.
        Later, this can be improved with tldextract.
        """

        if not hostname:
            return None

        parts = hostname.lower().strip(".").split(".")

        if len(parts) >= 2:
            return ".".join(parts[-2:])

        return hostname.lower()

    def _count_subdomains(self, hostname: str) -> int:
        parts = hostname.lower().strip(".").split(".")

        if len(parts) <= 2:
            return 0

        return len(parts) - 2

    def _decode_punycode(self, hostname: str) -> str:
        try:
            return hostname.encode("ascii").decode("idna")
        except Exception:
            return hostname

    def _analyze_sensitive_keywords(
        self,
        findings: List[Dict[str, Any]],
        parsed_url,
        original_url: str
    ) -> int:
        path_and_query = f"{parsed_url.path} {parsed_url.query}".lower()

        detected_keywords = [
            keyword for keyword in self.SENSITIVE_KEYWORDS
            if keyword in path_and_query
        ]

        if detected_keywords:
            self._add_finding(
                findings,
                severity="Low",
                score=3,
                finding="URL contains account or credential-related keywords.",
                explanation=(
                    f"The URL path/query contains sensitive keywords: "
                    f"{', '.join(sorted(set(detected_keywords)))}."
                ),
                url=original_url
            )

            return 3

        return 0

    def _analyze_brand_impersonation(
        self,
        findings: List[Dict[str, Any]],
        hostname: str,
        base_domain: str,
        original_url: str
    ) -> int:
        """
        Detect brand names or lookalike domains in URL hostnames.
        """

        score = 0
        hostname_lower = hostname.lower()
        base_domain_lower = base_domain.lower()

        for brand, allowed_domains in self.BRAND_DOMAINS.items():
            allowed_base_domains = {
                self._base_domain(domain)
                for domain in allowed_domains
            }

            # Case 1: exact allowed domain, safe for this brand
            if base_domain_lower in allowed_base_domains:
                continue

            # Case 2: brand name appears in suspicious domain
            if brand in hostname_lower:
                self._add_finding(
                    findings,
                    severity="High",
                    score=8,
                    finding="URL may be impersonating a trusted brand.",
                    explanation=(
                        f"The URL contains the brand name '{brand}', but the actual "
                        f"base domain is '{base_domain}', not an official known domain."
                    ),
                    url=original_url
                )
                return 8

            # Case 3: lookalike domain using string similarity
            for allowed_domain in allowed_base_domains:
                similarity = self._similarity(base_domain_lower, allowed_domain)
                distance = self._levenshtein_distance(base_domain_lower, allowed_domain)

                if similarity >= 0.85 or distance <= 2:
                    self._add_finding(
                        findings,
                        severity="High",
                        score=8,
                        finding="URL domain is similar to a trusted brand domain.",
                        explanation=(
                            f"The URL base domain '{base_domain}' is similar to "
                            f"'{allowed_domain}'. This may indicate typosquatting."
                        ),
                        url=original_url
                    )
                    return 8

        return score

    def _similarity(self, first: str, second: str) -> float:
        if not first or not second:
            return 0.0

        max_length = max(len(first), len(second))
        distance = self._levenshtein_distance(first, second)

        return 1 - (distance / max_length)

    def _levenshtein_distance(self, first: str, second: str) -> int:
        if first == second:
            return 0

        if len(first) < len(second):
            return self._levenshtein_distance(second, first)

        if len(second) == 0:
            return len(first)

        previous_row = list(range(len(second) + 1))

        for i, char_first in enumerate(first, start=1):
            current_row = [i]

            for j, char_second in enumerate(second, start=1):
                insertions = previous_row[j] + 1
                deletions = current_row[j - 1] + 1
                substitutions = previous_row[j - 1] + (char_first != char_second)

                current_row.append(min(insertions, deletions, substitutions))

            previous_row = current_row

        return previous_row[-1]

    def _add_finding(
        self,
        findings: List[Dict[str, Any]],
        severity: str,
        score: int,
        finding: str,
        explanation: str,
        url: str
    ) -> None:
        findings.append({
            "severity": severity,
            "score": score,
            "finding": finding,
            "explanation": explanation,
            "url": url,
            "mitre_mapping": [
                "T1566 - Phishing",
                "T1566.002 - Spearphishing Link"
            ]
        })

    def _classify_score(self, score: int) -> str:
        if score >= 14:
            return "HIGH_RISK_URL"

        if score >= 6:
            return "SUSPICIOUS_URL"

        return "LOW_RISK_URL"