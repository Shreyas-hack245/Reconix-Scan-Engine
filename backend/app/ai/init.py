"""
AI explanation / enrichment package for Reconix Scan Engine.

This package enriches raw scanner findings with human-readable risk
explanations, business impact statements, developer-facing guidance,
step-by-step remediation, formatted safe proof-of-concept output, and
false-positive-aware confidence scoring. The current implementation
uses a deterministic, template-driven engine keyed on vulnerability
type and severity so the application runs fully offline with no
external API dependency; `RiskExplainer.explain` is the single
integration point where a call to a hosted LLM could be substituted in
without changing any calling code.
"""