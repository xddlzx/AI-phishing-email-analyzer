from typing import Dict, Any, List
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification


class PhishingTextClassifier:
    """
    Text classification module for the AI-Powered Phishing Email Analyzer.

    This module uses:
    cybersectony/phishing-email-detection-distilbert_v2.4.1

    It only analyzes text. It does not send emails, open links,
    collect credentials, or perform any offensive action.
    """

    MODEL_NAME = "cybersectony/phishing-email-detection-distilbert_v2.4.1"

    def __init__(self):
        self.device = self._get_device()

        self.tokenizer = AutoTokenizer.from_pretrained(self.MODEL_NAME)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.MODEL_NAME)

        self.model.to(self.device)
        self.model.eval()

        self.id2label = self._resolve_id2label()
    
    def _resolve_id2label(self) -> Dict[int, str]:
        """
        Resolve model labels.

        Some Hugging Face models expose generic labels like LABEL_0, LABEL_1.
        The model card for cybersectony/phishing-email-detection-distilbert_v2.4.1
        shows four output classes:
            0 -> legitimate_email
            1 -> phishing_url
            2 -> legitimate_url
            3 -> phishing_url_alt

        If the model config only gives generic LABEL_n names, we map them manually.
        """

        configured_labels = dict(self.model.config.id2label)

        label_values = [
            str(configured_labels[index]).lower()
            for index in sorted(configured_labels.keys())
        ]

        uses_generic_labels = all(
            label.startswith("label_")
            for label in label_values
        )

        if uses_generic_labels and len(configured_labels) == 4:
            return {
                0: "legitimate_email",
                1: "phishing_url",
                2: "legitimate_url",
                3: "phishing_url_alt"
            }

        return configured_labels

    def _get_device(self) -> torch.device:
        """
        Select the best available device.
        - CUDA for NVIDIA GPU
        - MPS for Apple Silicon
        - CPU otherwise
        """
        if torch.cuda.is_available():
            return torch.device("cuda")

        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            return torch.device("mps")

        return torch.device("cpu")

    def predict(self, email_text: str) -> Dict[str, Any]:
        """
        Classify email text as safe/suspicious/phishing-like.

        Input:
            email_text: subject + body + visible URLs

        Output:
            Dictionary with raw label, confidence, phishing score,
            normalized classification, and all probabilities.
        """

        if not email_text or not email_text.strip():
            return {
                "module": "text_classification",
                "error": "Empty email text provided.",
                "classification": "UNKNOWN",
                "score": 0.0,
                "max_score": 40,
                "phishing_score": 0.0,
                "confidence": 0.0,
                "raw_prediction": None,
                "all_probabilities": {},
                "findings": [],
                "model_name": self.MODEL_NAME
            }

        inputs = self.tokenizer(
            email_text,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512
        )

        inputs = {key: value.to(self.device) for key, value in inputs.items()}

        with torch.no_grad():
            outputs = self.model(**inputs)

        probabilities = self._get_probabilities(outputs.logits)

        all_probabilities = {
            self.id2label[i]: float(probabilities[i])
            for i in range(len(probabilities))
        }

        raw_prediction = max(all_probabilities, key=all_probabilities.get)
        confidence = all_probabilities[raw_prediction]

        phishing_score = self._calculate_phishing_score(all_probabilities)
        classification = self._normalize_classification(phishing_score)

        findings = self._build_findings(
            classification=classification,
            phishing_score=phishing_score,
            raw_prediction=raw_prediction
        )

        return {
            "module": "text_classification",
            "text_score": round(phishing_score * 40, 2),
            "score": round(phishing_score * 40, 2),
            "max_score": 40,
            "classification": classification,
            "phishing_score": round(phishing_score, 4),
            "confidence": round(confidence, 4),
            "raw_prediction": raw_prediction,
            "all_probabilities": {
                label: round(score, 4)
                for label, score in all_probabilities.items()
            },
            "findings": findings,
            "model_name": self.MODEL_NAME
        }
    

    def _get_probabilities(self, logits: torch.Tensor) -> torch.Tensor:
        """
        Convert logits to probabilities.

        Some model cards say 'multilabel' but use softmax in examples.
        This function checks the model config first.
        """

        logits = logits[0]

        if self.model.config.problem_type == "multi_label_classification":
            return torch.sigmoid(logits).detach().cpu()

        return torch.softmax(logits, dim=-1).detach().cpu()
    

    def _calculate_phishing_score(self, probabilities: Dict[str, float]) -> float:
        """
        Calculate a general phishing score from model labels.

        This is robust because model labels may not be perfectly named.
        Any label containing 'phish' contributes to phishing risk.
        """

        phishing_labels = [
            label for label in probabilities
            if "phish" in label.lower()
        ]

        if not phishing_labels:
            return 0.0

        phishing_score = max(probabilities[label] for label in phishing_labels)

        return float(phishing_score)

    def _normalize_classification(self, phishing_score: float) -> str:
        """
        Convert model phishing score to project-level classification.

        These thresholds are only for the text classifier.
        Later, the final risk engine will combine this with
        header, URL, attachment, and social engineering signals.
        """

        if phishing_score >= 0.75:
            return "PHISHING"

        if phishing_score >= 0.40:
            return "SUSPICIOUS"

        return "SAFE"


    def _build_findings(
        self,
        classification: str,
        phishing_score: float,
        raw_prediction: str
    ) -> List[Dict[str, Any]]:
        """
        Build explanation-ready findings for the AI text classifier.
        """

        if classification == "SAFE":
            return []

        severity = "High" if classification == "PHISHING" else "Medium"

        return [
            {
                "severity": severity,
                "score": round(phishing_score * 40, 2),
                "finding": "AI text classifier detected phishing-like language.",
                "explanation": (
                    f"The model prediction was '{raw_prediction}' with a phishing "
                    f"score of {round(phishing_score, 4)}."
                ),
                "mitre_mapping": [
                    "T1566 - Phishing"
                ]
            }
        ]