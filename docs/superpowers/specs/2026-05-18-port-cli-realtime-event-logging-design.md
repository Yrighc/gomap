# Port CLI Realtime Event Logging Design

## Goal

Make verbose CLI logging truly realtime by emitting scan events from the execution pipeline at the moment an open port or service match is discovered, instead of waiting for batch completion.

## Approach

- Add an optional event callback to `assetprobe.Options`.
- Emit an `open_port` event during TCP discovery as soon as a port is confirmed open.
- Emit a `service_match` event during TCP fingerprinting as soon as service recognition finishes.
- Emit equivalent `open_port` / `service_match` events for UDP once a response is recognized as open.
- Let `gomap port -v` subscribe to these events and print Chinese stderr lines immediately.
- Let `gomap weak -v` reuse the same assetprobe realtime events for candidate discovery, and continue printing its own Chinese realtime hit logs when secprobe returns successful findings.

## Constraints

- Keep stdout JSON output unchanged.
- Keep event callback optional and no-op by default.
- Preserve existing scan result shapes and ordering.
- Realtime logs may appear in task completion order rather than sorted port order.

## Testing

- Add an `assetprobe` test that verifies an open-port event is emitted before `Scan` returns.
- Keep CLI tests focused on stderr wording and stdout compatibility.
