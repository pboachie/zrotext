"""Executable comparison examples; supply independently scoped client instances."""


def read_legacy_status(client, message_id):
    return client.get_status(message_id)


def read_generated_status(client, message_id):
    return client.public.alpha_messages.get_status(message_id=message_id)


def submit_legacy(client, intent, idempotency_key):
    """Persist the intent and key before this call; no retry is performed here."""
    return client.submit(**intent, idempotency_key=idempotency_key)


def preview_generated(client, intent, idempotency_key):
    return client.public.alpha_messages.preview_submit(**intent, opts={"idempotency_key": idempotency_key})


def submit_generated_reviewed(client, intent, idempotency_key, confirmation_token):
    """Caller reviews the preview separately; its token is not server approval."""
    return client.public.alpha_messages.submit(**intent, opts={
        "idempotency_key": idempotency_key, "confirm": confirmation_token,
    })


def needs_reconciliation(state):
    return state in ("unknown", "delivery_unknown")
