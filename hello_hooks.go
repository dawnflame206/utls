package tls

import (
	"errors"
	"io"
)

// Hello contains a snapshot of a TLS handshake message, including its header.
// PSKBinderLengths lists the sizes of the ClientHello PSK binders, in wire order.
type Hello struct {
	Wire             []byte
	Random           [32]byte
	ServerName       string
	PSKBinderLengths []int
}

// HelloHooks optionally supplies application-specific TLS 1.3 hello processing.
// Functions can be shared by connections if they are safe for concurrent use.
// TransformClientHello runs before writing the initial ClientHello for both
// Client and UClient. It can replace fixed-length fields without changing the
// fingerprint preset serialization.
// TransformServerHello runs before writing ServerHello on Server connections.
// TransformServerHello must return a 32-byte replacement random.
// VerifyServerHello returning true replaces certificate-chain and
// CertificateVerify authentication for this handshake. VerifyPeerCertificate
// and VerifyConnection still run. Returning false keeps ordinary TLS
// verification. This hook is skipped after HelloRetryRequest.
type HelloHooks struct {
	TransformClientHello func(Hello, io.Reader) (ClientHelloEdits, error)
	VerifyServerHello    func(Hello) (bool, error)
	VerifyClientHello    func(Hello) error
	TransformServerHello func(Hello, io.Reader) ([]byte, error)

	// HelloRetryRequestError aborts a server handshake that would require
	// HelloRetryRequest when set.
	HelloRetryRequestError error

	// SuppressEarlyAlerts enables TCP fallback before the server has written
	// anything, by discarding handshake output on failure.
	SuppressEarlyAlerts bool
}

// ClientHelloEdits replaces fields without changing their encoded lengths.
// Nil fields leave the corresponding bytes unchanged.
type ClientHelloEdits struct {
	Random    []byte
	SessionID []byte
}

func newClientHello(msg *clientHelloMsg) (Hello, error) {
	wire := msg.original
	if wire == nil {
		var err error
		wire, err = msg.marshal()
		if err != nil {
			return Hello{}, err
		}
	}
	hello := Hello{Wire: append([]byte(nil), wire...), Random: [32]byte(msg.random), ServerName: msg.serverName}
	for _, binder := range msg.pskBinders {
		hello.PSKBinderLengths = append(hello.PSKBinderLengths, len(binder))
	}
	return hello, nil
}

func newServerHello(msg *serverHelloMsg) (Hello, error) {
	wire := msg.original
	if wire == nil {
		var err error
		wire, err = msg.marshal()
		if err != nil {
			return Hello{}, err
		}
	}
	return Hello{Wire: append([]byte(nil), wire...), Random: [32]byte(msg.random)}, nil
}

func transformedHelloRandom(hello Hello, transform func(Hello, io.Reader) ([]byte, error), random io.Reader) ([]byte, error) {
	value, err := transform(hello, random)
	if err != nil {
		return nil, err
	}
	if len(value) != len(hello.Random) {
		return nil, errors.New("tls: hello hook must return a 32-byte random")
	}
	return append([]byte(nil), value...), nil
}

func (c *Conn) transformClientHello(msg *clientHelloMsg, session *SessionState, binderKey []byte) error {
	hooks := c.config.HelloHooks
	if hooks == nil || hooks.TransformClientHello == nil {
		return nil
	}
	if c.config.EncryptedClientHelloConfigList != nil {
		return errors.New("tls: ClientHello transform cannot be combined with ECH")
	}
	hello, err := newClientHello(msg)
	if err != nil {
		return err
	}
	edits, err := hooks.TransformClientHello(hello, c.config.rand())
	if err != nil {
		return err
	}
	if edits.Random == nil && edits.SessionID == nil {
		return nil
	}
	const randomOffset = 4 + 2 // Handshake header and legacy version.
	presetWire := msg.original != nil
	wire, err := msg.marshal()
	if err != nil {
		return err
	}
	wire = append([]byte(nil), wire...)
	if edits.Random != nil {
		if len(edits.Random) != 32 {
			return errors.New("tls: ClientHello hook must return a 32-byte random")
		}
		msg.random = wire[randomOffset : randomOffset+32]
		copy(msg.random, edits.Random)
	}
	if edits.SessionID != nil {
		if len(edits.SessionID) != len(msg.sessionId) {
			return errors.New("tls: ClientHello hook cannot change session ID length")
		}
		const sessionIDOffset = randomOffset + 32 + 1
		msg.sessionId = wire[sessionIDOffset : sessionIDOffset+len(edits.SessionID)]
		copy(msg.sessionId, edits.SessionID)
	}
	if presetWire {
		msg.original = wire
	}

	if len(msg.pskBinders) != 0 {
		if session == nil || binderKey == nil {
			return errors.New("tls: missing PSK binder key for ClientHello hook")
		}
		suite := cipherSuiteTLS13ByID(session.cipherSuite)
		if suite == nil {
			return errors.New("tls: no TLS 1.3 cipher suite for PSK binder")
		}
		if err := computeAndUpdatePSK(msg, binderKey, suite.hash.New(), suite.finishedHash); err != nil {
			return err
		}
		offset := len(wire)
		for i := len(msg.pskBinders) - 1; i >= 0; i-- {
			binder := msg.pskBinders[i]
			offset -= len(binder)
			copy(wire[offset:], binder)
			offset-- // Binder length prefix.
		}
	}
	return nil
}

func (c *Conn) verifyServerHello(msg *serverHelloMsg) error {
	hooks := c.config.HelloHooks
	if hooks == nil || hooks.VerifyServerHello == nil || c.didHRR {
		return nil
	}
	hello, err := newServerHello(msg)
	if err != nil {
		return err
	}
	c.serverHelloVerified, err = hooks.VerifyServerHello(hello)
	return err
}

func (c *Conn) verifyClientHello(msg *clientHelloMsg) error {
	hooks := c.config.HelloHooks
	if hooks == nil || hooks.VerifyClientHello == nil {
		return nil
	}
	hello, err := newClientHello(msg)
	if err != nil {
		return err
	}
	return hooks.VerifyClientHello(hello)
}

func (c *Conn) transformServerHello(msg *serverHelloMsg) error {
	hooks := c.config.HelloHooks
	if hooks == nil || hooks.TransformServerHello == nil {
		return nil
	}
	hello, err := newServerHello(msg)
	if err != nil {
		return err
	}
	msg.random, err = transformedHelloRandom(hello, hooks.TransformServerHello, c.config.rand())
	return err
}

func (c *Conn) suppressEarlyAlerts() bool {
	hooks := c.config.HelloHooks
	return !c.isClient && c.quic == nil && hooks != nil && hooks.SuppressEarlyAlerts && c.bytesSent == 0
}
