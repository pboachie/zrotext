# Delivery state model

Each state change needs evidence from the phone or a timeout. An ambiguous radio submission becomes `unknown` and is never retried automatically, because a retry could send a duplicate SMS. A conflicting callback in any active state also moves the message to `unknown`. See [message semantics](ARCHITECTURE.md#message-semantics-and-the-duplicate-send-problem).

```mermaid
stateDiagram-v2
    direction LR
    [*] --> accepted
    accepted --> queued: enqueue
    queued --> claimed: device claims
    claimed --> submitting: submit intent saved
    submitting --> submitted: sent callback OK
    submitting --> failed: sent callback failed
    submitting --> unknown: crash, timeout or partial
    claimed --> unknown: grant timeout
    unknown --> submitted: late sent callback
    unknown --> failed: late failure callback
    claimed --> queued: proven no submit
    submitting --> queued: proven no submit
    unknown --> queued: proven no submit
    submitted --> delivered: delivery callback
    submitted --> delivery_unknown: no receipt in time
    delivery_unknown --> delivered: late receipt
    accepted --> cancelled
    queued --> cancelled
    claimed --> cancelled
    accepted --> expired
    queued --> expired
    claimed --> expired
```

