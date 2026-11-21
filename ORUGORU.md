# Orugoru changes

This fork starts from uTLS commit `a13c59ffe98b`. Orugoru builds against
it through local module replacements.

The fork exposes TLS 1.3 hello callbacks in `hello_hooks.go`. They allow
callers to inspect the wire messages, replace hello random values before
they enter the transcript, and authenticate ServerHello as an alternative
to certificate authentication. Two server options control HelloRetryRequest
and allow fallback before the first TLS write. uTLS retains TLS framing,
transcript processing, and PSK binder recalculation. Orugoru implements JLS
authentication and fallback forwarding in its own transport package.

The fork also exposes a client record interface and a TLS 1.2 ECDHE key
selector. RESTLS uses these to try an alternate encoding of the first
protected record, observe the encrypted client Finished, and process
RESTLS application records. The ClientHello callback can replace a
fixed-length session ID or random without remarshal of a browser preset.
