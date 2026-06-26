from typing import Dict, Any, List, Union, Optional
from email import policy
from email.parser import Parser
import re


class PhishingAttachmentAnalyzer:
    """
    Attachment analysis module for the AI-Powered Phishing Email Analyzer.

    This module performs static defensive analysis only.
    It does not open, execute, extract, upload, or scan attachments.
    It only analyzes attachment names and file extensions.
    """

    MAX_SCORE = 10

    HIGH_RISK_EXTENSIONS = {
        "exe",
        "scr",
        "js",
        "jse",
        "vbs",
        "vbe",
        "bat",
        "cmd",
        "ps1",
        "psm1",
        "hta",
        "lnk",
        "msi",
        "com",
        "cpl",
        "jar",
        "wsf",
        "wsh",
    }

    MACRO_OFFICE_EXTENSIONS = {
        "docm",
        "xlsm",
        "pptm",
        "dotm",
        "xltm",
        "potm",
    }

    ARCHIVE_EXTENSIONS = {
        "zip",
        "rar",
        "7z",
        "gz",
        "tar",
        "iso",
        "img",
    }

    COMMON_DECOY_EXTENSIONS = {
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "txt",
        "jpg",
        "jpeg",
        "png",
        "gif",
    }

    SUSPICIOUS_KEYWORDS = {
        "invoice",
        "payment",
        "receipt",
        "bank",
        "salary",
        "bonus",
        "urgent",
        "confidential",
        "secure",
        "password",
        "account",
        "verification",
        "statement",
        "tax",
        "refund",
        "delivery",
        "shipment",
        "scan",
        "document",
    }

    FILENAME_PATTERN = re.compile(
        r"(?i)\b[\w\-().\[\] ]+\.(?:exe|scr|js|jse|vbs|vbe|bat|cmd|ps1|hta|lnk|msi|com|cpl|jar|wsf|wsh|docm|xlsm|pptm|dotm|xltm|potm|zip|rar|7z|gz|tar|iso|img|pdf|docx?|xlsx?|pptx?|txt|jpg|jpeg|png|gif)\b"
    )

    def analyze(self, input_data: Union[str, List[str]]) -> Dict[str, Any]:
        """
        Analyze attachment names.

        Args:
            input_data:
                - list of attachment filenames, or
                - raw email string containing MIME attachment metadata, or
                - plain text mentioning attachment filenames

        Returns:
            Dictionary containing module score, classification,
            analyzed attachments, and explanation-ready findings.
        """

        attachment_names = self._get_attachment_names(input_data)

        findings: List[Dict[str, Any]] = []
        analyzed_attachments: List[Dict[str, Any]] = []
        score = 0

        if not attachment_names:
            return {
                "module": "attachment_analysis",
                "score": 0,
                "max_score": self.MAX_SCORE,
                "classification": "NO_ATTACHMENTS_FOUND",
                "attachments_found": [],
                "findings": []
            }

        for filename in attachment_names:
            attachment_result = self._analyze_single_attachment(filename)
            analyzed_attachments.append(attachment_result)

            for finding in attachment_result["findings"]:
                findings.append(finding)
                score += finding["score"]

        final_score = min(score, self.MAX_SCORE)

        return {
            "module": "attachment_analysis",
            "score": final_score,
            "max_score": self.MAX_SCORE,
            "classification": self._classify_score(final_score),
            "attachments_found": analyzed_attachments,
            "findings": findings
        }

    def _get_attachment_names(self, input_data: Union[str, List[str]]) -> List[str]:
        """
        Get attachment names from either:
        - a list of filenames
        - a raw MIME email
        - a plain text sample
        """

        if isinstance(input_data, list):
            return self._deduplicate([
                self._clean_filename(filename)
                for filename in input_data
                if filename and filename.strip()
            ])

        if isinstance(input_data, str):
            mime_filenames = self._extract_filenames_from_mime(input_data)

            if mime_filenames:
                return self._deduplicate(mime_filenames)

            text_filenames = self._extract_filenames_from_text(input_data)
            return self._deduplicate(text_filenames)

        raise TypeError("input_data must be a raw email string or a list of filenames.")

    def _extract_filenames_from_mime(self, raw_email: str) -> List[str]:
        """
        Extract filenames from MIME Content-Disposition metadata.
        """

        filenames = []

        try:
            message = Parser(policy=policy.default).parsestr(raw_email)

            if not message.is_multipart():
                return []

            for part in message.walk():
                filename = part.get_filename()

                if filename:
                    filenames.append(self._clean_filename(filename))

        except Exception:
            return []

        return filenames

    def _extract_filenames_from_text(self, text: str) -> List[str]:
        """
        Fallback extractor for simple text examples.

        This only extracts filenames from attachment-related lines.
        It avoids treating domains such as gmail.com or mx.example.com
        as attachment filenames.
        """

        filenames = []

        attachment_context_keywords = [
            "attachment",
            "attached",
            "filename",
            "file:"
        ]

        for raw_line in text.splitlines():
            line = raw_line.strip()
            lower_line = line.lower()

            if not line:
                continue

            has_attachment_context = any(
                keyword in lower_line
                for keyword in attachment_context_keywords
            )

            if not has_attachment_context:
                continue

            matches = self.FILENAME_PATTERN.findall(line)

            for match in matches:
                cleaned = self._clean_filename(match)

                if self._is_probable_attachment_filename(cleaned):
                    filenames.append(cleaned)

        return self._deduplicate(filenames)
    
    def _is_probable_attachment_filename(self, filename: str) -> bool:
        """
        Avoid obvious non-attachment values.
        """

        lower_filename = filename.lower()

        if "://" in lower_filename:
            return False

        if "@" in lower_filename:
            return False

        if not self._extract_extensions(filename):
            return False

        return True

    def _clean_filename(self, filename: str) -> str:
        """
        Normalize attachment filename.
        """

        filename = filename.strip()
        filename = filename.strip("\"'")
        filename = filename.replace("\u202e", "[RLO]")
        filename = re.sub(r"\s+", " ", filename)

        return filename

    def _analyze_single_attachment(self, filename: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []

        extensions = self._extract_extensions(filename)
        final_extension = extensions[-1] if extensions else None
        lower_filename = filename.lower()

        # 1. No extension
        if not final_extension:
            self._add_finding(
                findings=findings,
                severity="Low",
                score=1,
                finding="Attachment has no clear file extension.",
                explanation=(
                    f"The attachment '{filename}' does not have a clear file extension. "
                    "This can make it harder for users to understand the file type."
                ),
                filename=filename
            )

        # 2. High-risk executable/script extensions
        if final_extension in self.HIGH_RISK_EXTENSIONS:
            self._add_finding(
                findings=findings,
                severity="High",
                score=8,
                finding="Attachment uses a high-risk executable or script extension.",
                explanation=(
                    f"The attachment '{filename}' ends with '.{final_extension}', "
                    "which can execute commands or code if opened."
                ),
                filename=filename
            )

        # 3. Macro-enabled Office files
        if final_extension in self.MACRO_OFFICE_EXTENSIONS:
            self._add_finding(
                findings=findings,
                severity="Medium",
                score=5,
                finding="Attachment is a macro-enabled Office file.",
                explanation=(
                    f"The attachment '{filename}' uses '.{final_extension}'. "
                    "Macro-enabled Office files are commonly used in phishing attachments."
                ),
                filename=filename
            )

        # 4. Archive or disk image attachment
        if final_extension in self.ARCHIVE_EXTENSIONS:
            severity = "Medium" if final_extension in {"iso", "img"} else "Low"
            finding_score = 5 if final_extension in {"iso", "img"} else 3

            self._add_finding(
                findings=findings,
                severity=severity,
                score=finding_score,
                finding="Attachment is an archive or disk image file.",
                explanation=(
                    f"The attachment '{filename}' uses '.{final_extension}'. "
                    "Archive and disk image files can hide risky files inside them."
                ),
                filename=filename
            )

        # 5. Double extension trick
        if self._has_double_extension(extensions):
            self._add_finding(
                findings=findings,
                severity="High",
                score=7,
                finding="Attachment uses a double-extension filename trick.",
                explanation=(
                    f"The attachment '{filename}' has multiple extensions: "
                    f"{', '.join(['.' + ext for ext in extensions])}. "
                    "This can mislead users about the real file type."
                ),
                filename=filename
            )

        # 6. Decoy extension followed by risky final extension
        if self._has_decoy_then_risky_extension(extensions):
            self._add_finding(
                findings=findings,
                severity="High",
                score=8,
                finding="Attachment appears to hide a risky extension behind a decoy extension.",
                explanation=(
                    f"The attachment '{filename}' appears to show a harmless-looking "
                    "extension before a risky final extension."
                ),
                filename=filename
            )

        # 7. Right-to-left override trick
        if "[RLO]" in filename:
            self._add_finding(
                findings=findings,
                severity="High",
                score=8,
                finding="Attachment filename contains a right-to-left override character.",
                explanation=(
                    "The filename contains a Unicode right-to-left override character. "
                    "Attackers may use this to visually disguise the real extension."
                ),
                filename=filename
            )

        # 8. Suspicious lure keywords in filename
        detected_keywords = [
            keyword for keyword in self.SUSPICIOUS_KEYWORDS
            if keyword in lower_filename
        ]

        if detected_keywords:
            self._add_finding(
                findings=findings,
                severity="Low",
                score=2,
                finding="Attachment filename contains common phishing lure keywords.",
                explanation=(
                    f"The filename contains lure-related keywords: "
                    f"{', '.join(sorted(set(detected_keywords)))}."
                ),
                filename=filename
            )

        return {
            "filename": filename,
            "extensions": extensions,
            "final_extension": final_extension,
            "findings": findings
        }

    def _extract_extensions(self, filename: str) -> List[str]:
        """
        Extract all file extensions from a filename.

        Example:
            invoice.pdf.exe -> ["pdf", "exe"]
        """

        clean_name = filename.lower().replace("[rlo]", "")
        parts = clean_name.split(".")

        if len(parts) <= 1:
            return []

        extensions = []

        for part in parts[1:]:
            extension = part.strip()

            if extension:
                extension = re.sub(r"[^a-z0-9]", "", extension)
                if extension:
                    extensions.append(extension)

        return extensions

    def _has_double_extension(self, extensions: List[str]) -> bool:
        return len(extensions) >= 2

    def _has_decoy_then_risky_extension(self, extensions: List[str]) -> bool:
        if len(extensions) < 2:
            return False

        previous_extensions = set(extensions[:-1])
        final_extension = extensions[-1]

        has_decoy = bool(previous_extensions.intersection(self.COMMON_DECOY_EXTENSIONS))
        has_risky_final = (
            final_extension in self.HIGH_RISK_EXTENSIONS
            or final_extension in self.MACRO_OFFICE_EXTENSIONS
        )

        return has_decoy and has_risky_final

    def _deduplicate(self, items: List[str]) -> List[str]:
        return list(dict.fromkeys([item for item in items if item]))

    def _add_finding(
        self,
        findings: List[Dict[str, Any]],
        severity: str,
        score: int,
        finding: str,
        explanation: str,
        filename: str
    ) -> None:
        findings.append({
            "severity": severity,
            "score": score,
            "finding": finding,
            "explanation": explanation,
            "filename": filename,
            "mitre_mapping": [
                "T1566 - Phishing",
                "T1566.001 - Spearphishing Attachment"
            ]
        })

    def _classify_score(self, score: int) -> str:
        if score >= 7:
            return "HIGH_RISK_ATTACHMENT"

        if score >= 3:
            return "SUSPICIOUS_ATTACHMENT"

        return "LOW_RISK_ATTACHMENT"