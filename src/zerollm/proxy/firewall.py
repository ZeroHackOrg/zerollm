# src/zerollm/proxy/firewall.py
import re


class SecurityException(Exception):
    pass


class ZeroLLMProxy:
    def __init__(self):
        self.INJECTION_SIGNATURES = [
            r"ignore previous instructions",
            r"system override",
            r"output the master key",
            r"act as a malicious terminal",
        ]
        self.CREDENTIAL_PATTERN = r"\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b"

    def sanitize_prompt(self, user_prompt: str) -> str:
        lowered_prompt = user_prompt.lower()
        for signature in self.INJECTION_SIGNATURES:
            if re.search(signature, lowered_prompt):
                raise SecurityException(
                    f"🚨 [ZeroLLM Attack Blocked] Intercepted Malicious System Hijack Pattern: '{signature}'"
                )

        sanitized_payload = re.sub(self.CREDENTIAL_PATTERN, "[REDACTED_FINANCIAL_DATA]", user_prompt)
        print("🔒 Prompt passed structural verification and corporate masking.", file=__import__("sys").stderr)
        return sanitized_payload