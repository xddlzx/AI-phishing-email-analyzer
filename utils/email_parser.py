from typing import Dict, Any, List
from email import policy
from email.parser import Parser
import re


class EmailParser:
    """
    Email parser for the AI-Powered Phishing Email Analyzer.

    It extracts:
    - headers
    - subject
    - body
    - attachment filenames
    - text prepared for AI analysis
    """

    def parse(self, raw_email: str) -> Dict[str, Any]:
        message = Parser(policy=policy.default).parsestr(raw_email)

        headers = self._extract_headers(message)
        subject = headers.get("subject", "")
        body = self._extract_body(message)
        attachment_names = self._extract_attachment_names(message)

        # This is what we send to the AI text model and social engineering analyzer.
        analysis_text = self._build_analysis_text(
            subject=subject,
            body=body,
            attachment_names=attachment_names
        )

        return {
            "raw_email": raw_email,
            "headers": headers,
            "subject": subject,
            "body": body,
            "attachment_names": attachment_names,
            "analysis_text": analysis_text
        }

    def _extract_headers(self, message) -> Dict[str, str]:
        headers = {}

        for key in message.keys():
            value = message.get(key, "")
            headers[key.lower()] = str(value)

        return headers

    def _extract_body(self, message) -> str:
        """
        Extract readable body text.

        Handles:
        - plain text emails
        - multipart emails
        - basic HTML fallback
        """

        if message.is_multipart():
            plain_parts = []
            html_parts = []

            for part in message.walk():
                content_disposition = part.get_content_disposition()
                content_type = part.get_content_type()

                # Skip attachments.
                if content_disposition == "attachment":
                    continue

                if content_type == "text/plain":
                    try:
                        plain_parts.append(part.get_content())
                    except Exception:
                        pass

                elif content_type == "text/html":
                    try:
                        html_parts.append(self._strip_html(part.get_content()))
                    except Exception:
                        pass

            if plain_parts:
                return "\n".join(plain_parts).strip()

            if html_parts:
                return "\n".join(html_parts).strip()

            return ""

        try:
            content_type = message.get_content_type()

            if content_type == "text/html":
                return self._strip_html(message.get_content()).strip()

            return str(message.get_content()).strip()

        except Exception:
            return ""

    def _extract_attachment_names(self, message) -> List[str]:
        attachment_names = []

        if not message.is_multipart():
            return attachment_names

        for part in message.walk():
            filename = part.get_filename()

            if filename:
                attachment_names.append(filename)

        return list(dict.fromkeys(attachment_names))

    def _build_analysis_text(
        self,
        subject: str,
        body: str,
        attachment_names: List[str]
    ) -> str:
        text = f"""
Subject:
{subject}

Body:
{body}
"""

        if attachment_names:
            text += "\nAttachments:\n"
            for attachment in attachment_names:
                text += f"- {attachment}\n"

        return text.strip()

    def _strip_html(self, html: str) -> str:
        html = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
        html = re.sub(r"(?is)<style.*?>.*?</style>", " ", html)
        html = re.sub(r"(?s)<.*?>", " ", html)
        html = re.sub(r"\s+", " ", html)

        return html.strip()