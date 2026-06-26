from typing import Dict, Any, List
import re


class SocialEngineeringAnalyzer:
    """
    Social engineering analysis module for the AI-Powered Phishing Email Analyzer.

    This module performs safe static text analysis only.
    It does not generate phishing emails, send emails, open links,
    collect credentials, or perform offensive actions.

    Purpose:
        Detect persuasion and manipulation indicators commonly used in
        phishing and spearphishing emails.
    """

    MAX_SCORE = 5

    CATEGORY_PATTERNS = {
        "urgency": {
            "severity": "Medium",
            "score": 2,
            "mitre_mapping": ["T1566 - Phishing"],
            "description": "The message uses urgency to pressure the recipient into quick action.",
            "patterns": [
                r"\burgent\b",
                r"\bimmediately\b",
                r"\bimmediate action\b",
                r"\bact now\b",
                r"\bwithin 24 hours\b",
                r"\btoday\b",
                r"\bfinal notice\b",
                r"\blast warning\b",
                r"\bdeadline\b",
                r"\btime sensitive\b",
                r"\bas soon as possible\b",
            ],
        },
        "fear_or_threat": {
            "severity": "Medium",
            "score": 2,
            "mitre_mapping": ["T1566 - Phishing"],
            "description": "The message uses fear, threats, or negative consequences.",
            "patterns": [
                r"\bsuspended\b",
                r"\bdisabled\b",
                r"\blocked\b",
                r"\bterminated\b",
                r"\bunauthorized access\b",
                r"\bsuspicious activity\b",
                r"\bunusual login\b",
                r"\baccount closure\b",
                r"\bwill be closed\b",
                r"\bsecurity breach\b",
                r"\bcompromised\b",
            ],
        },
        "credential_request": {
            "severity": "High",
            "score": 3,
            "mitre_mapping": [
                "T1566 - Phishing",
                "T1566.002 - Spearphishing Link"
            ],
            "description": "The message asks for login, password, verification, or account credentials.",
            "patterns": [
                r"\bverify your account\b",
                r"\bverify your identity\b",
                r"\bconfirm your identity\b",
                r"\blogin\b",
                r"\bsign in\b",
                r"\bsign-in\b",
                r"\bpassword\b",
                r"\bcredentials\b",
                r"\bmfa\b",
                r"\b2fa\b",
                r"\bone[- ]time password\b",
                r"\botp\b",
                r"\breset your password\b",
                r"\bupdate your password\b",
                r"\baccount verification\b",
            ],
        },
        "financial_lure": {
            "severity": "Medium",
            "score": 2,
            "mitre_mapping": ["T1566 - Phishing"],
            "description": "The message uses financial topics such as invoices, payments, refunds, or banking.",
            "patterns": [
                r"\binvoice\b",
                r"\bpayment\b",
                r"\bbank\b",
                r"\bbilling\b",
                r"\brefund\b",
                r"\btax\b",
                r"\bwire transfer\b",
                r"\btransaction\b",
                r"\breceipt\b",
                r"\bpurchase order\b",
                r"\boverdue\b",
                r"\bpayroll\b",
                r"\bsalary\b",
            ],
        },
        "authority_impersonation": {
            "severity": "Medium",
            "score": 2,
            "mitre_mapping": ["T1566 - Phishing"],
            "description": "The message appears to impersonate authority, support, security, or business roles.",
            "patterns": [
                r"\bsecurity team\b",
                r"\bit support\b",
                r"\bhelp desk\b",
                r"\badministrator\b",
                r"\badmin\b",
                r"\bceo\b",
                r"\bcfo\b",
                r"\bhr\b",
                r"\bhuman resources\b",
                r"\bfinance department\b",
                r"\bcompliance\b",
                r"\blegal department\b",
            ],
        },
        "attachment_lure": {
            "severity": "Medium",
            "score": 2,
            "mitre_mapping": [
                "T1566 - Phishing",
                "T1566.001 - Spearphishing Attachment"
            ],
            "description": "The message encourages the recipient to open or review an attachment.",
            "patterns": [
                r"\battached\b",
                r"\battachment\b",
                r"\bsee attached\b",
                r"\breview the attached\b",
                r"\bopen the attached\b",
                r"\battached invoice\b",
                r"\battached document\b",
                r"\bscan attached\b",
                r"\bdownload the attachment\b",
            ],
        },
        "link_click_lure": {
            "severity": "Medium",
            "score": 2,
            "mitre_mapping": [
                "T1566 - Phishing",
                "T1566.002 - Spearphishing Link"
            ],
            "description": "The message encourages clicking a link to complete an action.",
            "patterns": [
                r"\bclick here\b",
                r"\bfollow this link\b",
                r"\bvisit the link\b",
                r"\bopen the link\b",
                r"\buse the link below\b",
                r"\bclick the button\b",
                r"\baccess the portal\b",
                r"\bgo to the portal\b",
            ],
        },
        "service_impersonation": {
            "severity": "Medium",
            "score": 2,
            "mitre_mapping": [
                "T1566 - Phishing",
                "T1566.003 - Spearphishing via Service"
            ],
            "description": "The message references common platforms or third-party services often impersonated in phishing.",
            "patterns": [
                r"\bmicrosoft\b",
                r"\boffice 365\b",
                r"\boutlook\b",
                r"\bgoogle\b",
                r"\bgmail\b",
                r"\bpaypal\b",
                r"\bapple\b",
                r"\bamazon\b",
                r"\blinkedin\b",
                r"\bdropbox\b",
                r"\bdocusign\b",
                r"\bgithub\b",
                r"\bmeta\b",
                r"\bfacebook\b",
                r"\binstagram\b",
            ],
        },
    }

    def analyze(self, email_text: str) -> Dict[str, Any]:
        """
        Analyze email text for social engineering indicators.

        Args:
            email_text:
                Subject + body text. URLs may be included, but URL structure
                should be handled by url_analyzer.py.

        Returns:
            Dictionary containing module score, classification,
            detected categories, and explanation-ready findings.
        """

        if not email_text or not email_text.strip():
            return {
                "module": "social_engineering_analysis",
                "score": 0,
                "max_score": self.MAX_SCORE,
                "classification": "NO_TEXT_PROVIDED",
                "detected_categories": [],
                "findings": []
            }

        normalized_text = self._normalize_text(email_text)

        findings: List[Dict[str, Any]] = []
        detected_categories: List[str] = []
        raw_score = 0

        for category, config in self.CATEGORY_PATTERNS.items():
            matched_phrases = self._find_matches(
                text=normalized_text,
                patterns=config["patterns"]
            )

            if matched_phrases:
                detected_categories.append(category)
                raw_score += config["score"]

                self._add_finding(
                    findings=findings,
                    severity=config["severity"],
                    score=config["score"],
                    finding=f"Social engineering indicator detected: {category.replace('_', ' ')}.",
                    explanation=config["description"],
                    evidence=matched_phrases,
                    mitre_mapping=config["mitre_mapping"]
                )

        raw_score += self._analyze_risky_combinations(
            findings=findings,
            detected_categories=detected_categories
        )

        final_score = min(raw_score, self.MAX_SCORE)

        return {
            "module": "social_engineering_analysis",
            "score": final_score,
            "max_score": self.MAX_SCORE,
            "classification": self._classify_score(final_score),
            "detected_categories": detected_categories,
            "findings": findings
        }

    def _normalize_text(self, text: str) -> str:
        """
        Normalize text for safer pattern matching.
        """

        text = text.lower()
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def _find_matches(self, text: str, patterns: List[str]) -> List[str]:
        """
        Return unique matched phrases for a category.
        """

        matches = []

        for pattern in patterns:
            for match in re.findall(pattern, text, flags=re.IGNORECASE):
                if isinstance(match, tuple):
                    match = " ".join(match)

                if match:
                    matches.append(match.strip())

        return sorted(set(matches))

    def _analyze_risky_combinations(
        self,
        findings: List[Dict[str, Any]],
        detected_categories: List[str]
    ) -> int:
        """
        Add extra risk when multiple social engineering tactics appear together.
        """

        detected = set(detected_categories)
        extra_score = 0

        risky_combinations = [
            {
                "required": {"urgency", "credential_request"},
                "finding": "Urgency combined with credential request.",
                "explanation": (
                    "The email pressures the recipient to act quickly while also "
                    "asking for account verification, login, or password-related action."
                ),
                "mitre_mapping": [
                    "T1566 - Phishing",
                    "T1566.002 - Spearphishing Link"
                ],
            },
            {
                "required": {"fear_or_threat", "credential_request"},
                "finding": "Threat language combined with credential request.",
                "explanation": (
                    "The email uses negative consequences such as suspension or blocking "
                    "while asking for credential-related action."
                ),
                "mitre_mapping": [
                    "T1566 - Phishing",
                    "T1566.002 - Spearphishing Link"
                ],
            },
            {
                "required": {"financial_lure", "attachment_lure"},
                "finding": "Financial lure combined with attachment lure.",
                "explanation": (
                    "The email uses invoice, payment, or banking language while encouraging "
                    "the recipient to open an attachment."
                ),
                "mitre_mapping": [
                    "T1566 - Phishing",
                    "T1566.001 - Spearphishing Attachment"
                ],
            },
            {
                "required": {"service_impersonation", "link_click_lure"},
                "finding": "Service impersonation combined with link-click request.",
                "explanation": (
                    "The email references a known service or platform while encouraging "
                    "the recipient to click a link."
                ),
                "mitre_mapping": [
                    "T1566 - Phishing",
                    "T1566.002 - Spearphishing Link",
                    "T1566.003 - Spearphishing via Service"
                ],
            },
        ]

        for combination in risky_combinations:
            if combination["required"].issubset(detected):
                extra_score += 1

                self._add_finding(
                    findings=findings,
                    severity="High",
                    score=1,
                    finding=combination["finding"],
                    explanation=combination["explanation"],
                    evidence=sorted(combination["required"]),
                    mitre_mapping=combination["mitre_mapping"]
                )

        return extra_score

    def _add_finding(
        self,
        findings: List[Dict[str, Any]],
        severity: str,
        score: int,
        finding: str,
        explanation: str,
        evidence: List[str],
        mitre_mapping: List[str]
    ) -> None:
        findings.append({
            "severity": severity,
            "score": score,
            "finding": finding,
            "explanation": explanation,
            "evidence": evidence,
            "mitre_mapping": mitre_mapping
        })

    def _classify_score(self, score: int) -> str:
        if score >= 4:
            return "HIGH_SOCIAL_ENGINEERING_RISK"

        if score >= 2:
            return "SUSPICIOUS_SOCIAL_ENGINEERING"

        return "LOW_SOCIAL_ENGINEERING_RISK"