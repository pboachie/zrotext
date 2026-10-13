"""Native scoped workflow HTTPS client; schemas and results never confer authority."""
import copy
import http.client
import json
import queue
import re
import socket
import threading
import urllib.parse

import workflow_validation as validation

_STATUSES = {"invalid_request": 400, "unauthorized": 401, "forbidden": 403,
             "not_found": 404, "conflict": 409, "rate_limited": 429, "unavailable": 503}
# DNS cannot be cancelled by Python sockets. Bound outstanding workers, and check
# cancellation after connect so a delayed resolver never submits a timed-out call.
_WORKERS = threading.BoundedSemaphore(16)


class WorkflowError(Exception):
    """Redacted refusal or unknown result; no server diagnostics or credentials."""
    def __init__(self, code, state="refused", attempts=0):
        super().__init__(code)
        self.code, self.state, self.attempts = code, state, attempts


def workflow_functions():
    return validation.functions()


def action_digest(descriptor):
    try:
        return validation.action_digest(descriptor)
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise WorkflowError("invalid_request") from None


class WorkflowClient:
    def __init__(self, origin, credential, timeout_ms=10000):
        try:
            if (type(origin) is not str or type(credential) is not str
                    or type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000
                    or re.fullmatch(r"ztw_[A-Za-z0-9_-]{43}", credential) is None
                    or not validation.canonical_base64url(credential[4:])):
                raise ValueError()
            parsed = urllib.parse.urlsplit(origin)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.path not in ("", "/")
                    or parsed.query or parsed.fragment or any(ord(c) < 33 for c in origin)
                    or "\\" in origin):
                raise ValueError()
            self.__host, self.__port = parsed.hostname.encode("idna").decode(), parsed.port
            self.__credential, self.__timeout = credential, timeout_ms / 1000
        except (ValueError, TypeError, UnicodeError):
            raise WorkflowError("invalid_configuration") from None

    def __repr__(self):
        return "WorkflowClient(<credential redacted>)"

    def _exchange(self, body):
        """One bounded attempt with TLS verification, no redirects/proxies/cookies."""
        if not _WORKERS.acquire(blocking=False):
            raise TimeoutError()
        connection = http.client.HTTPSConnection(self.__host, self.__port, timeout=self.__timeout)
        cancelled = threading.Event()
        result = queue.Queue(maxsize=1)

        def run():
            try:
                connection.connect()
                if cancelled.is_set():
                    raise TimeoutError()
                headers = {"Authorization": "Bearer " + self.__credential, "Accept": "application/json",
                           "Cache-Control": "no-store"}
                if body is not None:
                    headers["Content-Type"] = "application/json"
                connection.request("GET" if body is None else "POST", "/v1/workflow/tools", body=body, headers=headers)
                response = connection.getresponse()
                if cancelled.is_set():
                    raise TimeoutError()
                content_type = response.getheader("Content-Type", "")
                data = response.read(131073)
                if len(data) > 131072 or response.length not in (None, 0) or cancelled.is_set():
                    raise ValueError()
                result.put((response.status, content_type, data))
            except Exception:
                result.put(None)
            finally:
                connection.close()
                _WORKERS.release()

        try:
            threading.Thread(target=run, daemon=True).start()
        except Exception:
            _WORKERS.release()
            connection.close()
            raise
        try:
            value = result.get(timeout=self.__timeout)
            if value is None:
                raise ValueError()
            return value
        except queue.Empty:
            cancelled.set()
            active = connection.sock
            if active is not None:
                try:
                    active.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                active.close()
            raise TimeoutError() from None

    def _request(self, body, max_attempts):
        for attempt in range(1, max_attempts + 1):
            try:
                status, content_type, raw = self._exchange(body)
                if (re.fullmatch(r"application/json(?:\s*;\s*charset=utf-8)?", content_type, re.I) is None
                        or len(raw) > 131072):
                    raise ValueError()
                value = json.loads(raw.decode("utf-8"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                if status == 200:
                    return value, attempt
                if (type(value) is not dict or set(value) != {"error"} or type(value["error"]) is not dict
                        or set(value["error"]) != {"code"} or type(value["error"]["code"]) is not str
                        or _STATUSES.get(value["error"]["code"]) != status):
                    raise ValueError()
                code = value["error"]["code"]
                if code == "rate_limited" and attempt < max_attempts:
                    continue
                raise WorkflowError(code, "unknown" if code == "unavailable" else "refused", attempt)
            except WorkflowError:
                raise
            except Exception:
                raise WorkflowError("response_unknown", "unknown", attempt) from None
        raise WorkflowError("response_unknown", "unknown", max_attempts)

    def readiness(self):
        value, attempts = self._request(None, 1)
        try:
            validation.readiness(value)
            return value
        except (ValueError, TypeError, KeyError, RecursionError):
            raise WorkflowError("response_unknown", "unknown", attempts) from None

    def call(self, method, params, max_attempts=1):
        try:
            if (type(method) is not str or type(params) is not dict or type(max_attempts) is not int
                    or not 1 <= max_attempts <= 3):
                raise ValueError()
            snapshot = copy.deepcopy(params)
            validation.request(method, snapshot)
            snapshot = validation.wire_numbers(snapshot)
            body = json.dumps({"method": method, "params": snapshot}, ensure_ascii=False,
                              separators=(",", ":"), allow_nan=False).encode("utf-8")
            if len(body) > 65536:
                raise ValueError()
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise WorkflowError("invalid_request") from None
        value, attempts = self._request(body, max_attempts)
        try:
            validation.response(method, value, snapshot)
            return value
        except (ValueError, TypeError, KeyError, RecursionError):
            raise WorkflowError("response_unknown", "unknown", attempts) from None

    def preview(self, request_id, descriptor):
        return self.call("workflow.action.propose", {"request_id": request_id, "descriptor": descriptor})

    def status(self, request_id, context_id, action_id):
        return self.call("workflow.action.status", {"request_id": request_id, "context_id": context_id, "action_id": action_id})

    def submit(self, request_id, key, occurrence_id=None):
        return self.call("workflow.action.send", {"request_id": request_id, "key": key, "occurrence_id": occurrence_id})

    def cancel(self, request_id, key):
        return self.call("workflow.action.cancel", {"request_id": request_id, "key": key})
