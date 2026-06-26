from typing import Dict, Any, List, Union, Optional
from email import policy
from email.parser import Parser
from email.utils import parseaddr
import re


class PhishingHeaderAnalyzer:
    """
    Header analysis module for the AI-Powered Phishing Email Analyzer.

    This module performs static defensive analysis only.
    It does not send emails, verify live DNS records, open links,
    collect credentials, or perform offensive actions.
    """

    MAX_SCORE = 25

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

    AUTH_RESULT_PATTERN = re.compile(
        r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
        re.IGNORECASE
    )

    def analyze(self, email_input: Union[str, Dict[str, str]]) -> Dict[str, Any]:
        """
        Analyze email headers.

        Args:
            email_input:
                - raw email string containing headers, or
                - dictionary of headers

        Returns:
            Dictionary containing risk score, findings, parsed sender info,
            authentication results, and explanation-ready output.
        """

        headers = self._normalize_headers(email_input)

        findings: List[Dict[str, Any]] = []
        score = 0

        from_header = self._get_first_header(headers, "from")
        reply_to_header = self._get_first_header(headers, "reply-to")
        return_path_header = self._get_first_header(headers, "return-path")
        sender_header = self._get_first_header(headers, "sender")
        message_id_header = self._get_first_header(headers, "message-id")
        authentication_results = self._get_all_headers(headers, "authentication-results")
        received_headers = self._get_all_headers(headers, "received")

        from_name, from_email = parseaddr(from_header or "")
        reply_to_name, reply_to_email = parseaddr(reply_to_header or "")
        return_path_name, return_path_email = parseaddr(return_path_header or "")
        sender_name, sender_email = parseaddr(sender_header or "")

        from_domain = self._extract_domain(from_email)
        reply_to_domain = self._extract_domain(reply_to_email)
        return_path_domain = self._extract_domain(return_path_email)
        sender_domain = self._extract_domain(sender_email)
        message_id_domain = self._extract_message_id_domain(message_id_header)

        auth_results = self._parse_authentication_results(authentication_results)

        # 1. Missing From header
        if not from_header:
            score += self._add_finding(
                findings,
                severity="High",
                score=10,
                finding="Missing From header.",
                explanation="A valid email should normally contain a From header.",
                mitre_mapping=["T1566 - Phishing"]
            )

        # 2. Authentication analysis: SPF / DKIM / DMARC
        score += self._analyze_authentication_results(findings, auth_results, authentication_results)

        # 3. From vs Reply-To mismatch
        if from_domain and reply_to_domain:
            if self._base_domain(from_domain) != self._base_domain(reply_to_domain):
                score += self._add_finding(
                    findings,
                    severity="Medium",
                    score=7,
                    finding="From and Reply-To domains do not match.",
                    explanation=(
                        f"The email appears to come from '{from_domain}', "
                        f"but replies go to '{reply_to_domain}'."
                    ),
                    mitre_mapping=["T1566 - Phishing"]
                )

        # 4. From vs Return-Path mismatch
        if from_domain and return_path_domain:
            if self._base_domain(from_domain) != self._base_domain(return_path_domain):
                score += self._add_finding(
                    findings,
                    severity="Low",
                    score=3,
                    finding="From and Return-Path domains do not match.",
                    explanation=(
                        f"From domain is '{from_domain}', but Return-Path domain is "
                        f"'{return_path_domain}'. This can be legitimate in mailing systems, "
                        f"but it is also common in spoofed or relayed emails."
                    ),
                    mitre_mapping=["T1566 - Phishing"]
                )

        # 5. Sender header mismatch
        if from_domain and sender_domain:
            if self._base_domain(from_domain) != self._base_domain(sender_domain):
                score += self._add_finding(
                    findings,
                    severity="Low",
                    score=3,
                    finding="From and Sender domains do not match.",
                    explanation=(
                        f"From domain is '{from_domain}', while Sender domain is "
                        f"'{sender_domain}'. This may indicate delegated sending or spoofing."
                    ),
                    mitre_mapping=["T1566 - Phishing"]
                )

        # 6. Display-name spoofing
        if from_name and from_domain:
            score += self._analyze_display_name_spoofing(
                findings=findings,
                display_name=from_name,
                sender_domain=from_domain
            )

        # 7. Sender domain similarity to trusted brands
        if from_domain:
            score += self._analyze_domain_similarity(
                findings=findings,
                sender_domain=from_domain
            )

        # 8. Message-ID domain mismatch
        if from_domain and message_id_domain:
            if self._base_domain(from_domain) != self._base_domain(message_id_domain):
                score += self._add_finding(
                    findings,
                    severity="Low",
                    score=2,
                    finding="Message-ID domain does not match From domain.",
                    explanation=(
                        f"From domain is '{from_domain}', but Message-ID domain is "
                        f"'{message_id_domain}'. This is not always malicious, but it can "
                        f"support other spoofing indicators."
                    ),
                    mitre_mapping=["T1566 - Phishing"]
                )

        # 9. Missing Received headers
        if not received_headers:
            score += self._add_finding(
                findings,
                severity="Low",
                score=2,
                finding="No Received headers found.",
                explanation=(
                    "Full emails usually contain Received headers showing mail relay path. "
                    "This may be missing because the sample is incomplete."
                ),
                mitre_mapping=["T1566 - Phishing"]
            )

        final_score = min(score, self.MAX_SCORE)

        return {
            "module": "header_analysis",
            "score": final_score,
            "max_score": self.MAX_SCORE,
            "classification": self._classify_score(final_score),
            "sender": {
                "from_display_name": from_name,
                "from_email": from_email,
                "from_domain": from_domain,
                "reply_to_email": reply_to_email,
                "reply_to_domain": reply_to_domain,
                "return_path_email": return_path_email,
                "return_path_domain": return_path_domain,
                "sender_email": sender_email,
                "sender_domain": sender_domain,
                "message_id_domain": message_id_domain,
            },
            "authentication": auth_results,
            "header_presence": {
                "from": bool(from_header),
                "reply_to": bool(reply_to_header),
                "return_path": bool(return_path_header),
                "sender": bool(sender_header),
                "message_id": bool(message_id_header),
                "authentication_results": bool(authentication_results),
                "received_headers_count": len(received_headers),
            },
            "findings": findings
        }

    def _normalize_headers(self, email_input: Union[str, Dict[str, str]]) -> Dict[str, List[str]]:
        """
        Normalize raw email or dictionary input into:
        {
            "header-name": ["value1", "value2"]
        }
        """

        normalized: Dict[str, List[str]] = {}

        if isinstance(email_input, dict):
            for key, value in email_input.items():
                normalized.setdefault(key.lower(), []).append(str(value))
            return normalized

        if isinstance(email_input, str):
            message = Parser(policy=policy.default).parsestr(email_input)

            for key in message.keys():
                values = message.get_all(key, [])
                normalized[key.lower()] = [str(value) for value in values]

            return normalized

        raise TypeError("email_input must be a raw email string or a dictionary of headers.")

    def _get_first_header(self, headers: Dict[str, List[str]], name: str) -> Optional[str]:
        values = headers.get(name.lower(), [])
        return values[0] if values else None

    def _get_all_headers(self, headers: Dict[str, List[str]], name: str) -> List[str]:
        return headers.get(name.lower(), [])

    def _extract_domain(self, email_address: str) -> Optional[str]:
        if not email_address or "@" not in email_address:
            return None

        domain = email_address.split("@")[-1].strip().lower()
        domain = domain.strip("<>")
        return domain or None

    def _extract_message_id_domain(self, message_id: Optional[str]) -> Optional[str]:
        if not message_id:
            return None

        match = re.search(r"@([^>\s]+)", message_id)
        if not match:
            return None

        return match.group(1).lower().strip()

    def _base_domain(self, domain: str) -> str:
        """
        Simple base-domain extraction.

        Example:
            mail.security.example.com -> example.com

        This is enough for the first version.
        Later we can improve it using tldextract.
        """

        if not domain:
            return ""

        parts = domain.lower().split(".")

        if len(parts) >= 2:
            return ".".join(parts[-2:])

        return domain.lower()

    def _parse_authentication_results(self, auth_headers: List[str]) -> Dict[str, str]:
        """
        Extract SPF, DKIM, and DMARC results from Authentication-Results headers.
        """

        results = {
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown"
        }

        combined_headers = " ".join(auth_headers)

        for match in self.AUTH_RESULT_PATTERN.finditer(combined_headers):
            auth_type = match.group(1).lower()
            auth_result = match.group(2).lower()
            results[auth_type] = auth_result

        return results

    def _analyze_authentication_results(
        self,
        findings: List[Dict[str, Any]],
        auth_results: Dict[str, str],
        authentication_headers: List[str]
    ) -> int:
        score = 0

        if not authentication_headers:
            score += self._add_finding(
                findings,
                severity="Low",
                score=2,
                finding="Authentication-Results header is missing.",
                explanation=(
                    "SPF, DKIM, and DMARC results could not be checked because "
                    "the email sample does not contain Authentication-Results headers."
                ),
                mitre_mapping=["T1566 - Phishing"]
            )
            return score

        for auth_type, result in auth_results.items():
            if result in ["fail", "softfail", "permerror"]:
                severity = "High" if auth_type == "dmarc" else "Medium"
                finding_score = 10 if auth_type == "dmarc" else 7

                score += self._add_finding(
                    findings,
                    severity=severity,
                    score=finding_score,
                    finding=f"{auth_type.upper()} authentication result is '{result}'.",
                    explanation=(
                        f"{auth_type.upper()} did not pass. This may indicate spoofing, "
                        f"unauthorized sending infrastructure, or suspicious mail routing."
                    ),
                    mitre_mapping=["T1566 - Phishing"]
                )

            elif result in ["none", "neutral", "temperror"]:
                score += self._add_finding(
                    findings,
                    severity="Low",
                    score=2,
                    finding=f"{auth_type.upper()} authentication result is '{result}'.",
                    explanation=(
                        f"{auth_type.upper()} did not provide a clear pass result. "
                        f"This is not automatically malicious, but it weakens sender trust."
                    ),
                    mitre_mapping=["T1566 - Phishing"]
                )

        return score

    def _analyze_display_name_spoofing(
        self,
        findings: List[Dict[str, Any]],
        display_name: str,
        sender_domain: str
    ) -> int:
        score = 0
        display_name_lower = display_name.lower()

        for brand, allowed_domains in self.BRAND_DOMAINS.items():
            if brand in display_name_lower:
                sender_base = self._base_domain(sender_domain)

                allowed = any(
                    sender_base == self._base_domain(domain)
                    for domain in allowed_domains
                )

                if not allowed:
                    score += self._add_finding(
                        findings,
                        severity="High",
                        score=10,
                        finding="Possible display-name spoofing detected.",
                        explanation=(
                            f"The display name contains '{brand}', but the sender domain "
                            f"is '{sender_domain}', which is not an expected domain for that brand."
                        ),
                        mitre_mapping=["T1566 - Phishing"]
                    )

                break

        return score

    def _analyze_domain_similarity(
        self,
        findings: List[Dict[str, Any]],
        sender_domain: str
    ) -> int:
        score = 0
        sender_base = self._base_domain(sender_domain)

        for brand, allowed_domains in self.BRAND_DOMAINS.items():
            for allowed_domain in allowed_domains:
                allowed_base = self._base_domain(allowed_domain)

                if sender_base == allowed_base:
                    continue

                similarity = self._similarity(sender_base, allowed_base)
                distance = self._levenshtein_distance(sender_base, allowed_base)

                if similarity >= 0.85 or distance <= 2:
                    score += self._add_finding(
                        findings,
                        severity="High",
                        score=10,
                        finding="Sender domain is similar to a trusted brand domain.",
                        explanation=(
                            f"Sender domain '{sender_base}' is similar to '{allowed_base}'. "
                            f"This may indicate typosquatting or brand impersonation."
                        ),
                        mitre_mapping=["T1566 - Phishing"]
                    )
                    return score

        return score

    def _similarity(self, first: str, second: str) -> float:
        """
        Basic normalized similarity using Levenshtein distance.
        """

        if not first or not second:
            return 0.0

        max_length = max(len(first), len(second))
        distance = self._levenshtein_distance(first, second)

        return 1 - (distance / max_length)

    def _levenshtein_distance(self, first: str, second: str) -> int:
        """
        Compute Levenshtein distance without external dependencies.
        """

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
        mitre_mapping: List[str]
    ) -> int:
        findings.append({
            "severity": severity,
            "score": score,
            "finding": finding,
            "explanation": explanation,
            "mitre_mapping": mitre_mapping
        })

        return score

    def _classify_score(self, score: int) -> str:
        if score >= 16:
            return "HIGH_RISK_HEADER"

        if score >= 7:
            return "SUSPICIOUS_HEADER"

        return "LOW_RISK_HEADER"