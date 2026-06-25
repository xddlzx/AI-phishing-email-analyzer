from typing import Dict, Any
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

        self.id2label = self.model.config.id2label

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
                "error": "Empty email text provided.",
                "classification": "UNKNOWN",
                "phishing_score": 0.0,
                "confidence": 0.0,
                "raw_prediction": None,
                "all_probabilities": {}
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

        return {
            "classification": classification,
            "phishing_score": round(phishing_score, 4),
            "confidence": round(confidence, 4),
            "raw_prediction": raw_prediction,
            "all_probabilities": {
                label: round(score, 4)
                for label, score in all_probabilities.items()
            },
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