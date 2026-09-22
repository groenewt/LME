"""Identity-aware browser access for the LME dashboard."""

from .proxy import IdentityPolicy, ProxyConfiguration, create_app
from .config import resolved_role_config

__all__ = ["IdentityPolicy", "ProxyConfiguration", "create_app", "resolved_role_config"]
