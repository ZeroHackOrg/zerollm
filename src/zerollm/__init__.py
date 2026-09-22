# src/zerollm/__init__.py
"""ZeroLLM - automated AI firewall & prompt-injection sandbox."""

from .config import Config, ConfigError, load_config
from .detect.engine import DetectionEngine, Finding
from .policy import PolicyEngine
from .proxy import SecurityException, ZeroLLMHTTPGateway, ZeroLLMProxy

__version__ = "1.0.0"

__all__ = [
    "Config",
    "ConfigError",
    "DetectionEngine",
    "Finding",
    "PolicyEngine",
    "SecurityException",
    "ZeroLLMHTTPGateway",
    "ZeroLLMProxy",
    "__version__",
    "load_config",
]
