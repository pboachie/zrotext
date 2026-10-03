# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit customer-local owner authentication and narrow grant setup."""
from __future__ import annotations
import http.client
import json
import re
import ssl
from http.cookies import SimpleCookie
from urllib.parse import urlsplit
import uuid
from workflow_secret_store import credential


class OwnerSetupError(Exception):
    pass


def identity(value):
    try:
        parsed = uuid.UUID(value)
        if not parsed.int or str(parsed) != value:
            raise ValueError()
        return value
    except (ValueError, AttributeError):
        raise OwnerSetupError("invalid_scope") from None


def scope(value):
    fields = {"connector_id", "context_id", "contact_id", "purpose", "expires_at_ms"}
    if not isinstance(value, dict) or set(value) != fields:
        raise OwnerSetupError("invalid_scope")
    for key in ["connector_id", "context_id", "contact_id"]:
        identity(value[key])
    if value["purpose"] not in ["transactional", "operational", "marketing"]:
        raise OwnerSetupError("invalid_scope")
    if type(value["expires_at_ms"]) is not int or value["expires_at_ms"] <= 0:
        raise OwnerSetupError("invalid_scope")
    return dict(value, permissions=["context_metadata", "status"],
                signer_key_id=None, content_envelope_base64url=None)


class OwnerSession:
    """One bounded HTTPS owner session; never stored or supplied to MCP."""
    def __init__(self, origin, connection=None):
        parsed = urlsplit(origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                or origin.endswith("/")):
            raise OwnerSetupError("invalid_origin")
        self.origin = origin
        self.connection = connection or http.client.HTTPSConnection(
            parsed.hostname, parsed.port or 443, timeout=10, context=ssl.create_default_context())
        self.cookies = {}
        self.session_identity = None
        self.retain_creator = False

    def request(self, method, path, body=None):
        allowed = {("POST", "/v1/auth/login"), ("POST", "/v1/auth/login/mfa"),
                   ("GET", "/v1/auth/session"), ("POST", "/v1/auth/logout"),
                   ("POST", "/v1/auth/workflow-grants")}
        if (method, path) not in allowed and not (
                method == "DELETE" and re.fullmatch(r"/v1/auth/(?:workflow-grants|sessions)/[0-9a-f-]{36}", path)):
            raise OwnerSetupError("invalid_operation")
        encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        if encoded is not None and len(encoded) > 4096:
            raise OwnerSetupError("request_limit")
        headers = {"Origin": self.origin, "Accept": "application/json"}
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        if self.cookies:
            headers["Cookie"] = "; ".join(k + "=" + v for k, v in self.cookies.items())
            headers["x-zrotext-csrf"] = self.cookies.get("__Host-zrotext_csrf", "")
        try:
            self.connection.request(method, path, body=encoded, headers=headers)
            response = self.connection.getresponse()
            raw = response.read(65537)
            if len(raw) > 65536:
                raise OwnerSetupError("response_limit")
            for name, value in response.getheaders():
                if name.lower() == "set-cookie":
                    cookie = SimpleCookie()
                    cookie.load(value)
                    for key in ["__Host-zrotext_session", "__Host-zrotext_csrf"]:
                        if key in cookie:
                            if not cookie[key]["secure"] or cookie[key]["path"] != "/" or cookie[key]["domain"]:
                                raise OwnerSetupError("invalid_session")
                            self.cookies[key] = cookie[key].value
            data = json.loads(raw) if raw else None
            return response.status, data
        except (OSError, http.client.HTTPException, ValueError):
            # No automatic retry: an effectful response may have been lost.
            raise OwnerSetupError("owner_response_unknown") from None

    def login(self, email, password, mfa_code):
        status, data = self.request("POST", "/v1/auth/login", {"email": email, "password": password})
        if status == 202 and isinstance(data, dict) and set(data) == {"challenge_token"}:
            status, _ = self.request("POST", "/v1/auth/login/mfa",
                                     {"challenge_token": data["challenge_token"], "code": mfa_code()})
        if status != 200:
            raise OwnerSetupError("owner_authentication_refused")
        status, data = self.request("GET", "/v1/auth/session")
        if (status != 200 or not isinstance(data, dict)
                or set(data) != {"account_id", "user_id", "session_id", "role"}
                or data.get("role") != "owner"):
            raise OwnerSetupError("owner_required")
        if not all(self.cookies.get(k) for k in ["__Host-zrotext_session", "__Host-zrotext_csrf"]):
            raise OwnerSetupError("invalid_session")
        self.session_identity = {key: identity(data[key]) for key in ("account_id", "user_id", "session_id")}
        return self.session_identity["account_id"]

    def create(self, selected, password, grant_code):
        body = scope(selected)
        body.update(current_password=password, code=grant_code)
        status, data = self.request("POST", "/v1/auth/workflow-grants", body)
        if status != 201 or not isinstance(data, dict) or set(data) != {"grant_id", "token"}:
            raise OwnerSetupError("grant_refused_or_unknown")
        return identity(data["grant_id"]), credential(data["token"])

    def revoke(self, grant):
        status, _ = self.request("DELETE", "/v1/auth/workflow-grants/" + identity(grant))
        if status != 204:
            raise OwnerSetupError("revocation_unconfirmed")

    def revoke_creator(self, creator):
        if (not isinstance(creator, dict) or set(creator) != {"account_id", "user_id", "session_id"}
                or self.session_identity is None):
            raise OwnerSetupError("recovery_identity_refused")
        for key in creator:
            identity(creator[key])
        if any(creator[key] != self.session_identity[key] for key in ("account_id", "user_id")):
            raise OwnerSetupError("recovery_identity_refused")
        status, _ = self.request("DELETE", "/v1/auth/sessions/" + creator["session_id"])
        if status != 204:
            raise OwnerSetupError("revocation_unconfirmed")

    def close(self):
        try:
            if self.cookies and not self.retain_creator:
                self.request("POST", "/v1/auth/logout")
        except OwnerSetupError:
            pass
        finally:
            self.cookies.clear()
            self.connection.close()
