"""
Rakef Client integration using the authorizer_* API.
The rakef-client package is used directly in the code.
"""
import logging
from typing import Any, Optional

log = logging.getLogger(__name__)

try:
    from rakef_client import (
        AuthorizerGenerateIdentityOptions,
        authorizer_generate_identity,
    )
except ImportError:
    authorizer_generate_identity = None
    AuthorizerGenerateIdentityOptions = None
    log.error("rakef-client not installed. Rakef initialization will fail.")


class RakefAuthorizer:
    """
    Thin wrapper around the rakef authorizer_* API.
    Holds auth_url and client_token (issuer token) for generating identities.
    """

    def __init__(self, auth_url: str, client_token: str):
        self.auth_url = auth_url
        self.client_token = client_token

    async def generate_identity(
        self,
        *,
        email: Optional[str] = None,
        expires_in_days: int = 30,
        context_attributes: Optional[dict[str, Any]] = None,
    ):
        """Generate an identity token via authorizer_generate_identity."""
        if authorizer_generate_identity is None or AuthorizerGenerateIdentityOptions is None:
            raise RuntimeError("rakef-client not installed")
        options = AuthorizerGenerateIdentityOptions(
            client_token=self.client_token,
            auth_url=self.auth_url,
            email=email,
            expires_in_days=expires_in_days,
            context_attributes=context_attributes or {},
        )
        return await authorizer_generate_identity(options)


async def initialize_rakef_tool(
    auth_url: str, tool_name: str, client_token: str = ""
) -> Optional[RakefAuthorizer]:
    """
    Initialize Rakef: optionally verify connection, then return a RakefAuthorizer
    that uses the new authorizer_* API (client_token is the issuer token).
    """
    if authorizer_generate_identity is None or AuthorizerGenerateIdentityOptions is None:
        log.error("rakef-client package not installed. Cannot initialize Rakef.")
        return None
    if not auth_url or not client_token:
        log.warning("Rakef auth_url or client_token not set. Rakef disabled.")
        return None

    # Note: authorizer_verify_connection expects an access token; we only have
    # issuer token (client_token) here for generate_identity. Skip verify at startup.
    log.info(f"Rakef initialized with auth URL: {auth_url}")
    return RakefAuthorizer(auth_url=auth_url, client_token=client_token)
