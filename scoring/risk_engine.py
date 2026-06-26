from typing import Dict, Any, List, Optional


class PhishingRiskEngine:
    """
    Final scoring engine for the AI-Powered Phishing Email Analyzer.

    This engine combines all module-level results into one final risk result.

    It uses two layers:
        1. Overall weighted score
        2. Component-level risk override

    Important design decision:
        - Hard technical evidence can force PHISHING.
        - Soft signals such as AI text classification and social engineering
          should not force PHISHING alone.
    """

    MAX_TOTAL_SCORE = 100

    HIGH_COMPONENT_RATIO = 0.75
    SUSPICIOUS_COMPONENT_RATIO = 0.40

    PHISHING_OVERRIDE_COMPONENTS = {
        "header_analysis",
        "url_analysis",
        "attachment_analysis"
    }

    SOFT_SIGNAL_COMPONENTS = {
        "text_classification",
        "social_engineering_analysis"
    }

    COMPONENTS = {
        "text_classification": {
            "display_name": "AI Text Classifier",
            "expected_max_score": 40
        },
        "header_analysis": {
            "display_name": "Header/Auth Analysis",
            "expected_max_score": 25
        },
        "url_analysis": {
            "display_name": "URL Analysis",
            "expected_max_score": 20
        },
        "attachment_analysis": {
            "display_name": "Attachment Analysis",
            "expected_max_score": 10
        },
        "social_engineering_analysis": {
            "display_name": "Social Engineering Analysis",
            "expected_max_score": 5
        }
    }

    def calculate_final_risk(
        self,
        text_result: Optional[Dict[str, Any]] = None,
        header_result: Optional[Dict[str, Any]] = None,
        url_result: Optional[Dict[str, Any]] = None,
        attachment_result: Optional[Dict[str, Any]] = None,
        social_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Combine component results into a final phishing risk decision.
        """

        raw_components = {
            "text_classification": text_result,
            "header_analysis": header_result,
            "url_analysis": url_result,
            "attachment_analysis": attachment_result,
            "social_engineering_analysis": social_result
        }

        components = {}
        total_score = 0.0
        total_max_score = 0.0

        all_findings: List[Dict[str, Any]] = []
        mitre_mapping = set()

        for component_name, component_result in raw_components.items():
            normalized_component = self._normalize_component(
                component_name=component_name,
                component_result=component_result
            )

            components[component_name] = normalized_component

            total_score += normalized_component["score"]
            total_max_score += normalized_component["max_score"]

            for finding in normalized_component.get("findings", []):
                all_findings.append({
                    "component": component_name,
                    "component_display_name": normalized_component["display_name"],
                    **finding
                })

                for technique in finding.get("mitre_mapping", []):
                    mitre_mapping.add(technique)

        normalized_total_score = self._normalize_total_score(
            total_score=total_score,
            total_max_score=total_max_score
        )

        overall_score_classification = self._classify_by_overall_score(
            normalized_total_score
        )

        component_risk_result = self._evaluate_component_risk(components)

        final_classification = self._combine_overall_and_component_risk(
            overall_classification=overall_score_classification,
            component_risk_result=component_risk_result
        )

        component_override_applied = self._was_component_override_applied(
            overall_classification=overall_score_classification,
            final_classification=final_classification
        )

        explanation = self._build_explanation(
            final_classification=final_classification,
            overall_score_classification=overall_score_classification,
            normalized_total_score=normalized_total_score,
            component_risk_result=component_risk_result,
            component_override_applied=component_override_applied
        )

        return {
            "module": "final_risk_engine",
            "final_classification": final_classification,
            "overall_score": round(normalized_total_score, 2),
            "max_score": self.MAX_TOTAL_SCORE,
            "overall_score_classification": overall_score_classification,
            "component_override_applied": component_override_applied,
            "high_risk_component_detected": bool(component_risk_result["high_risk_components"]),
            "suspicious_component_detected": bool(component_risk_result["suspicious_components"]),
            "component_override_reason": (
                component_risk_result["override_reason"]
                if component_override_applied
                else None
            ),
            "high_risk_components": component_risk_result["high_risk_components"],
            "hard_high_risk_components": component_risk_result["hard_high_risk_components"],
            "soft_high_risk_components": component_risk_result["soft_high_risk_components"],
            "suspicious_components": component_risk_result["suspicious_components"],
            "components": components,
            "mitre_mapping": sorted(mitre_mapping),
            "findings": self._sort_findings(all_findings),
            "explanation": explanation
        }

    def _normalize_component(
        self,
        component_name: str,
        component_result: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Ensure every component has:
            score
            max_score
            risk_ratio
            component_classification
            findings
        """

        component_config = self.COMPONENTS[component_name]
        expected_max_score = component_config["expected_max_score"]

        if not component_result:
            return {
                "display_name": component_config["display_name"],
                "score": 0.0,
                "max_score": expected_max_score,
                "risk_ratio": 0.0,
                "risk_percentage": 0.0,
                "component_classification": "NOT_ANALYZED",
                "raw_classification": "NOT_ANALYZED",
                "findings": [],
                "raw_result": None
            }

        score = float(component_result.get("score", 0.0))
        max_score = float(component_result.get("max_score", expected_max_score))

        if max_score <= 0:
            max_score = expected_max_score

        score = min(score, max_score)
        risk_ratio = score / max_score

        component_classification = self._classify_component_ratio(risk_ratio)

        return {
            "display_name": component_config["display_name"],
            "score": round(score, 2),
            "max_score": round(max_score, 2),
            "risk_ratio": round(risk_ratio, 4),
            "risk_percentage": round(risk_ratio * 100, 2),
            "component_classification": component_classification,
            "raw_classification": component_result.get("classification", "UNKNOWN"),
            "findings": component_result.get("findings", []),
            "raw_result": component_result
        }

    def _normalize_total_score(
        self,
        total_score: float,
        total_max_score: float
    ) -> float:
        """
        Convert available component scores to a 0-100 score.
        """

        if total_max_score <= 0:
            return 0.0

        return (total_score / total_max_score) * self.MAX_TOTAL_SCORE

    def _classify_component_ratio(self, risk_ratio: float) -> str:
        """
        Component-level classification.

        Example:
            URL score 15/20 = 0.75 = HIGH_RISK_COMPONENT
        """

        if risk_ratio >= self.HIGH_COMPONENT_RATIO:
            return "HIGH_RISK_COMPONENT"

        if risk_ratio >= self.SUSPICIOUS_COMPONENT_RATIO:
            return "SUSPICIOUS_COMPONENT"

        return "LOW_RISK_COMPONENT"

    def _classify_by_overall_score(self, overall_score: float) -> str:
        """
        Overall score-based classification.
        """

        if overall_score >= 60:
            return "PHISHING"

        if overall_score >= 30:
            return "SUSPICIOUS"

        return "SAFE"

    def _evaluate_component_risk(self, components: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Check individual component risk.

        Hard evidence components can escalate final classification to PHISHING:
            - Header/Auth Analysis
            - URL Analysis
            - Attachment Analysis

        Soft evidence components should not force PHISHING alone:
            - AI Text Classifier
            - Social Engineering Analysis
        """

        high_risk_components = []
        suspicious_components = []
        hard_high_risk_components = []
        soft_high_risk_components = []

        for component_name, component in components.items():
            component_classification = component["component_classification"]

            component_summary = {
                "component": component_name,
                "display_name": component["display_name"],
                "score": component["score"],
                "max_score": component["max_score"],
                "risk_percentage": component["risk_percentage"],
                "raw_classification": component["raw_classification"]
            }

            if component_classification == "HIGH_RISK_COMPONENT":
                high_risk_components.append(component_summary)

                if component_name in self.PHISHING_OVERRIDE_COMPONENTS:
                    hard_high_risk_components.append(component_summary)

                elif component_name in self.SOFT_SIGNAL_COMPONENTS:
                    soft_high_risk_components.append(component_summary)

            elif component_classification == "SUSPICIOUS_COMPONENT":
                suspicious_components.append(component_summary)

        if hard_high_risk_components:
            return {
                "override_applied": True,
                "override_level": "PHISHING",
                "override_reason": (
                    "At least one hard-evidence component reached high-risk level "
                    "based on its own score ratio."
                ),
                "high_risk_components": high_risk_components,
                "hard_high_risk_components": hard_high_risk_components,
                "soft_high_risk_components": soft_high_risk_components,
                "suspicious_components": suspicious_components
            }

        if soft_high_risk_components or suspicious_components:
            return {
                "override_applied": True,
                "override_level": "SUSPICIOUS",
                "override_reason": (
                    "At least one soft-signal or suspicious component indicates elevated risk, "
                    "but there is not enough hard technical evidence to force PHISHING."
                ),
                "high_risk_components": high_risk_components,
                "hard_high_risk_components": hard_high_risk_components,
                "soft_high_risk_components": soft_high_risk_components,
                "suspicious_components": suspicious_components
            }

        return {
            "override_applied": False,
            "override_level": "NONE",
            "override_reason": None,
            "high_risk_components": [],
            "hard_high_risk_components": [],
            "soft_high_risk_components": [],
            "suspicious_components": []
        }

    def _combine_overall_and_component_risk(
        self,
        overall_classification: str,
        component_risk_result: Dict[str, Any]
    ) -> str:
        """
        Final classification is the higher-risk result between:
            - overall score classification
            - component-level override classification
        """

        risk_order = {
            "SAFE": 0,
            "SUSPICIOUS": 1,
            "PHISHING": 2,
            "NONE": -1
        }

        component_override_level = component_risk_result["override_level"]

        overall_level = risk_order.get(overall_classification, 0)
        component_level = risk_order.get(component_override_level, -1)

        if component_level > overall_level:
            return component_override_level

        return overall_classification

    def _was_component_override_applied(
        self,
        overall_classification: str,
        final_classification: str
    ) -> bool:
        """
        Return True only if component-level logic actually raised the final risk level.
        """

        risk_order = {
            "SAFE": 0,
            "SUSPICIOUS": 1,
            "PHISHING": 2
        }

        return risk_order.get(final_classification, 0) > risk_order.get(overall_classification, 0)

    def _build_explanation(
        self,
        final_classification: str,
        overall_score_classification: str,
        normalized_total_score: float,
        component_risk_result: Dict[str, Any],
        component_override_applied: bool
    ) -> List[str]:
        """
        Build short human-readable explanations for the final decision.
        """

        explanation = []

        explanation.append(
            f"Overall score-based classification is {overall_score_classification} "
            f"with a score of {round(normalized_total_score, 2)}/100."
        )

        if component_risk_result["hard_high_risk_components"]:
            component_names = [
                component["display_name"]
                for component in component_risk_result["hard_high_risk_components"]
            ]

            explanation.append(
                "Hard high-risk component(s) detected: "
                f"{', '.join(component_names)}."
            )

        if component_risk_result["soft_high_risk_components"]:
            component_names = [
                component["display_name"]
                for component in component_risk_result["soft_high_risk_components"]
            ]

            explanation.append(
                "Soft high-risk component(s) detected: "
                f"{', '.join(component_names)}."
            )

        if component_risk_result["suspicious_components"]:
            component_names = [
                component["display_name"]
                for component in component_risk_result["suspicious_components"]
            ]

            explanation.append(
                "Suspicious component(s) detected: "
                f"{', '.join(component_names)}."
            )

        if component_override_applied:
            explanation.append(
                "Final classification was escalated because component-level risk "
                "was higher than the overall score-based classification."
            )

        explanation.append(
            f"Final classification is {final_classification}."
        )

        return explanation

    def _sort_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sort findings by severity so high-risk findings appear first.
        """

        severity_order = {
            "High": 3,
            "Medium": 2,
            "Low": 1
        }

        return sorted(
            findings,
            key=lambda finding: severity_order.get(finding.get("severity"), 0),
            reverse=True
        )