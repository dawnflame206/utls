package tls

// ClientRecordContext describes the negotiated parameters and read state.
type ClientRecordContext struct {
	Version           uint16
	CipherSuite       uint16
	ServerRandom      [32]byte
	Protected         bool
	HandshakeComplete bool
}

// ClientRecordHooks customizes TCP records on a client connection. Use a
// separate instance for each connection. Read and Write may run concurrently.
type ClientRecordHooks struct {
	// A second open attempt is valid only after a failed authenticated decryption.
	Read func(ctx ClientRecordContext, record []byte, open func([]byte) ([]byte, byte, error)) ([]byte, byte, error)
	// Returning handled=false leaves the write to TLS.
	Write func(data []byte, write func([]byte) (int, error)) (n int, handled bool, err error)
	// ClientFinished observes the encoded and encrypted Finished record.
	ClientFinished func(record []byte)
}

func (c *Conn) setClientRecordContext(hello *serverHelloMsg) {
	if c.quic == nil && c.config.ClientRecordHooks != nil {
		c.clientRecordContext = &ClientRecordContext{
			Version: c.vers, CipherSuite: hello.cipherSuite, ServerRandom: [32]byte(hello.random),
		}
	}
}

func (c *Conn) openClientRecord(record []byte, complete bool) ([]byte, recordType, error) {
	if c.clientRecordContext == nil || c.config.ClientRecordHooks.Read == nil {
		return c.in.decrypt(record)
	}
	ctx := *c.clientRecordContext
	ctx.Protected = c.in.cipher != nil
	ctx.HandshakeComplete = complete
	data, typ, err := c.config.ClientRecordHooks.Read(ctx, record, func(record []byte) ([]byte, byte, error) {
		data, typ, err := c.in.decrypt(record)
		return data, byte(typ), err
	})
	return data, recordType(typ), err
}
