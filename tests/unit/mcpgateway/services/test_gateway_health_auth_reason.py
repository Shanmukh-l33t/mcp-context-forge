# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/services/test_gateway_health_auth_reason.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Regression tests for gateway health-check classification of HTTP 401/403
responses and the ``reachability_reason`` field on ``GatewayRead``.

Issue: a gateway that answers 401 or 403 was marked Offline after
``unhealthy_threshold`` cycles for every auth type except
``authorization_code``. The health check only inspected the response status
when the grant type was ``authorization_code``, so a wrong API key, bearer
token, basic credential or ``client_credentials`` secret was recorded as a
connectivity failure (``_handle_gateway_failure``) and the gateway flipped
to unreachable.

Covers:
- 401/403 on a non-``authorization_code`` gateway stays reachable and
  records ``reachability_reason="auth_failed"`` instead of counting a
  connectivity failure.
- the health-check failure threshold records
  ``reachability_reason="unreachable"`` alongside ``reachable=False``.
- ``GatewayRead.reachability_reason`` is an enumerated field.
"""

# Future
from __future__ import annotations

# Standard
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

# Third-Party
import httpx
from pydantic import ValidationError
import pytest

# First-Party
from mcpgateway.db import Gateway as DbGateway
from mcpgateway.schemas import GatewayRead
from mcpgateway.services import gateway_service as gateway_service_module
from mcpgateway.services.gateway_service import GatewayService


def _make_gateway(*, enabled=True, reachable=True, transport="sse", auth_type="authheaders", oauth_config=None, auth_value=None):
    """Create a mock gateway row for health-check tests."""
    gateway = MagicMock(spec=DbGateway)
    gateway.id = "test-gw-auth-reason"
    gateway.name = "Test Gateway Auth Reason"
    gateway.url = "https://example.com"
    gateway.transport = transport
    gateway.auth_type = auth_type
    gateway.oauth_config = oauth_config
    gateway.enabled = enabled
    gateway.reachable = reachable
    gateway.auth_value = auth_value if auth_value is not None else {"X-API-Key": "wrong-key"}
    gateway.auth_query_params = None
    gateway.ca_certificate = None
    gateway.client_cert = None
    gateway.client_key = None
    gateway.last_refresh_at = datetime.now(timezone.utc)
    return gateway


def _http_status_error(status_code: int) -> httpx.HTTPStatusError:
    """Build the httpx error the SSE probe raises on a non-2xx response."""
    response = MagicMock()
    response.status_code = status_code
    return httpx.HTTPStatusError(f"{status_code}", request=MagicMock(), response=response)


class _SyncCM:
    """Context manager yielding a fixed object (fresh_db_session / SessionLocal)."""

    def __init__(self, obj):
        self.obj = obj

    def __enter__(self):
        return self.obj

    def __exit__(self, *exc):
        return False


class _StreamClientCM:
    """Async context manager exposing a client.stream() that raises on enter."""

    def __init__(self, status_code: int):
        self.status_code = status_code

    async def __aenter__(self):
        client = MagicMock()
        stream_cm = MagicMock()
        err = _http_status_error(self.status_code)

        async def _aenter(*args, **kwargs):
            raise err

        stream_cm.__aenter__ = _aenter
        stream_cm.__aexit__ = AsyncMock(return_value=False)
        client.stream = MagicMock(return_value=stream_cm)
        return client

    async def __aexit__(self, *exc):
        return False


async def _run_health_check(gateway, status_code: int, *, user_email="admin@example.com"):
    """Run one health check against a gateway whose SSE probe answers status_code.

    Returns (service, update_db, status_db) so assertions can inspect the
    mock sessions and the mocked service methods.
    """
    service = GatewayService()
    service._handle_gateway_failure = AsyncMock()
    service.set_gateway_state = AsyncMock()

    update_db = MagicMock()
    db_gateway = MagicMock()
    db_gateway.enabled = gateway.enabled
    update_db.execute = MagicMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=db_gateway)))

    status_db = MagicMock()

    with (
        patch("mcpgateway.services.gateway_service.settings", MagicMock(enable_ed25519_signing=False, health_check_timeout=5, auto_refresh_servers=False)),
        patch("mcpgateway.services.gateway_service.get_isolated_http_client", return_value=_StreamClientCM(status_code)),
        patch("mcpgateway.services.gateway_service.fresh_db_session", side_effect=[_SyncCM(update_db)]),
        patch("mcpgateway.services.gateway_service.SessionLocal", return_value=_SyncCM(status_db)),
    ):
        await service._check_single_gateway_health(gateway, user_email=user_email)

    return service, update_db, status_db, db_gateway


class Test401ClassificationForAllAuthTypes:
    """401/403 must mean reachable-but-unauthorized for every auth type."""

    @pytest.mark.asyncio
    async def test_401_on_authheaders_gateway_is_not_a_connectivity_failure(self):
        """An invalid API key (authheaders) answers 401 - that is not unreachable."""
        gateway = _make_gateway(auth_type="authheaders", oauth_config=None)
        service, update_db, _status_db, db_gateway = await _run_health_check(gateway, 401)

        # The probe reached a live server that rejected the credential:
        # it must NOT be recorded as a connectivity failure.
        service._handle_gateway_failure.assert_not_called()

        # The reason is persisted so GatewayRead can report auth_failed.
        assert db_gateway.reachability_reason == "auth_failed"
        assert db_gateway.last_seen is not None
        update_db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_403_on_bearer_gateway_is_not_a_connectivity_failure(self):
        """A forbidden response on a bearer gateway also stays reachable."""
        gateway = _make_gateway(auth_type="bearer", oauth_config=None, auth_value={"Authorization": "Bearer stale"})
        service, _update_db, _status_db, db_gateway = await _run_health_check(gateway, 403)

        service._handle_gateway_failure.assert_not_called()
        assert db_gateway.reachability_reason == "auth_failed"

    @pytest.mark.asyncio
    async def test_401_on_client_credentials_gateway_is_not_a_connectivity_failure(self):
        """OAuth client_credentials with a revoked secret answers 401 - reachable."""
        gateway = _make_gateway(auth_type="oauth", oauth_config={"grant_type": "client_credentials"}, auth_value=None)
        service = GatewayService()
        service._handle_gateway_failure = AsyncMock()
        service.set_gateway_state = AsyncMock()
        service.oauth_manager = MagicMock()
        service.oauth_manager.get_access_token = AsyncMock(return_value="access-token")

        update_db = MagicMock()
        db_gateway = MagicMock()
        db_gateway.enabled = gateway.enabled
        update_db.execute = MagicMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=db_gateway)))
        status_db = MagicMock()

        with (
            patch("mcpgateway.services.gateway_service.settings", MagicMock(enable_ed25519_signing=False, health_check_timeout=5, auto_refresh_servers=False)),
            patch("mcpgateway.services.gateway_service.get_isolated_http_client", return_value=_StreamClientCM(401)),
            patch("mcpgateway.services.gateway_service.fresh_db_session", side_effect=[_SyncCM(update_db)]),
            patch("mcpgateway.services.gateway_service.SessionLocal", return_value=_SyncCM(status_db)),
        ):
            await service._check_single_gateway_health(gateway, user_email="admin@example.com")

        service._handle_gateway_failure.assert_not_called()
        assert db_gateway.reachability_reason == "auth_failed"

    @pytest.mark.asyncio
    async def test_auth_challenge_clears_previous_unreachable_state(self):
        """A gateway that was Offline and now answers 401 is reactivated as reachable."""
        gateway = _make_gateway(auth_type="authheaders", oauth_config=None, reachable=False)
        service, _update_db, _status_db, db_gateway = await _run_health_check(gateway, 401)

        service._handle_gateway_failure.assert_not_called()
        # Reactivation happened (reachable snapshot was False) and the
        # enumerated reason records why the gateway answers but stays guarded.
        service.set_gateway_state.assert_called_once()
        assert service.set_gateway_state.call_args[1]["reachable"] is True
        assert db_gateway.reachability_reason == "auth_failed"


class TestUnreachableReason:
    """The failure threshold records an enumerated unreachable reason."""

    @pytest.mark.asyncio
    async def test_failure_threshold_records_unreachable_reason(self, monkeypatch):
        """When the health-check failure threshold trips, the reason is 'unreachable'."""
        monkeypatch.setattr(gateway_service_module, "GW_FAILURE_THRESHOLD", 3)
        service = GatewayService()
        service.set_gateway_state = AsyncMock()
        service._gateway_failure_counts.clear()

        gateway = _make_gateway(auth_type="authheaders", oauth_config=None, reachable=True, enabled=True)
        gateway.reachable = True

        # Two prior failures; this one is the third and trips the threshold.
        service._gateway_failure_counts[gateway.id] = 2
        await service._handle_gateway_failure(gateway, error=Exception("connection refused"))

        assert service.set_gateway_state.call_count == 1
        kwargs = service.set_gateway_state.call_args[1]
        assert kwargs["reachable"] is False
        assert kwargs["reachability_reason"] == "unreachable"


class TestGatewayReadReachabilityReason:
    """GatewayRead exposes the enumerated reason for clients."""

    def test_reason_defaults_to_none(self):
        read = GatewayRead(name="gw", url="https://example.com")
        assert read.reachability_reason is None

    def test_reason_accepts_enumerated_values(self):
        assert GatewayRead(name="gw", url="https://example.com", reachability_reason="auth_failed").reachability_reason == "auth_failed"
        assert GatewayRead(name="gw", url="https://example.com", reachability_reason="unreachable").reachability_reason == "unreachable"

    def test_reason_rejects_unknown_values(self):
        with pytest.raises(ValidationError):
            GatewayRead(name="gw", url="https://example.com", reachability_reason="on_fire")
