# Port CLI Verbose Hit Logging Design

## Goal

Improve `gomap port` CLI readability in verbose mode by printing clear hit logs when an open port is found or when service fingerprinting matches a service, without changing the existing JSON stdout contract.

## Scope

- Only affect `gomap port`.
- Only emit the new hit logs when `-v` is enabled.
- Keep final scan result JSON on stdout unchanged.
- Send hit logs to stderr so machine-readable stdout consumers are not broken.

## Proposed Behavior

For each open port in the final `assetprobe.ScanResult`:

- Print one concise stderr line describing the open port hit.
- If the port also has a non-empty service match, include service information in the same line instead of printing a second line.
- If version information exists, include it as an extra field.

Example shape:

- `port hit target=demo resolved_ip=127.0.0.1 protocol=tcp port=80 open=true`
- `port hit target=demo resolved_ip=127.0.0.1 protocol=tcp port=80 open=true service=http version=nginx/1.25`

## Constraints

- No additional logs when `-v` is absent.
- No logs for closed ports.
- No changes to CSV output behavior.
- No changes to weak-probe JSON envelope behavior.

## Testing

- Add a CLI test that runs `gomap port -v` with a stubbed result containing:
  - one open port with service match
  - one open port without service match
- Assert:
  - stdout still contains the JSON result
  - stderr contains open-port hit lines
  - stderr contains service details only for the matched service port
