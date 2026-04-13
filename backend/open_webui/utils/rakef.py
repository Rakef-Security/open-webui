"""
Rakef Client integration using the authorizer_* API.
The rakef-client package is used directly in the code.
"""
import logging
from typing import Any, Optional

from fastapi import HTTPException, status

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


async def generate_rakef_identity_for_chat(
    rakef_tool: Optional[RakefAuthorizer],
    user_email: str,
    user_id: str,
    chat: Optional[dict] = None,
) -> str:
    """Generate Rakef identity for chat creation.

    Raises HTTPException if Rakef is unavailable or identity generation fails.
    """
    if not rakef_tool:
        log.error("Rakef tool is not available. Cannot create chat.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Chat creation service is temporarily unavailable. Please try again later."
        )

    # Derive model from chat (FE sends "models" list or "model" single value)
    model_name = None
    if chat:
        if isinstance(chat.get("models"), list) and chat["models"]:
            model_name = chat["models"][0]
        else:
            model_name = chat.get("model")

    attributes = {"chat": "openwebui"}
    if model_name:
        attributes["model"] = model_name

    try:
        identity_response = await rakef_tool.generate_identity(
            email=user_email,
            expires_in_days=30,
            context_attributes=attributes,
        )
        if identity_response and identity_response.identity:
            rakef_identity = identity_response.identity
            log.info(f"Generated Rakef identity for user {user_id} (email: {user_email}): {rakef_identity}")
            return rakef_identity
        else:
            log.error(f"Rakef identity generation returned empty result for user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create new chat. Please try again."
            )
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Failed to generate Rakef identity for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create new chat. Please try again."
        )


def get_rakef_identity(chat_id: Optional[str], user_id: str) -> Optional[str]:
    """Get Rakef identity from chat meta if available."""
    from open_webui.models.chats import Chats

    if chat_id and not chat_id.startswith("local:"):
        chat = Chats.get_chat_by_id_and_user_id(chat_id, user_id)
        if chat and chat.meta and chat.meta.get("rakef_identity"):
            return chat.meta["rakef_identity"]
    return None


def inject_rakef_identity_header(headers: dict, chat_id: Optional[str], user_id: str) -> None:
    """Inject x-rakef-identity header if a Rakef identity exists for this chat."""
    identity = get_rakef_identity(chat_id, user_id)
    if identity:
        headers['x-rakef-identity'] = identity
