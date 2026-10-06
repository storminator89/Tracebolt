//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Go previously accepted the fixture's empty issuer/subject names while
// OpenSSL treated the server leaf as self-signed. Exercise the actual shared
// fixture with Python's exact capability-client policy. MemoryBIO does not
// create a socket, listener, service, trust grant or external request.
func TestManagerFixtureTLSWorksWithPythonVerification(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("Python is required for the offline TLS fixture check")
	}
	ca, cert, key, _, _, _ := fixtureTLS(t)
	otherCA, _, _, _, _, _ := fixtureTLS(t)
	dir := t.TempDir()
	for name, raw := range map[string][]byte{"ca.pem": ca, "server.pem": cert, "server.key": key, "other-ca.pem": otherCA} {
		if os.WriteFile(filepath.Join(dir, name), raw, 0600) != nil {
			t.Fatal("offline TLS fixture write failed")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", "-c", `import pathlib, ssl, sys
p = pathlib.Path(sys.argv[1])
def handshake(ca, hostname):
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.minimum_version = ssl.TLSVersion.TLSv1_3
    client.load_verify_locations(cadata=(p / ca).read_text())
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.load_cert_chain(str(p / 'server.pem'), str(p / 'server.key'))
    ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
    c = client.wrap_bio(ci, co, server_hostname=hostname)
    s = server.wrap_bio(si, so, server_side=True)
    for _ in range(20):
        for peer in (c, s):
            try:
                peer.do_handshake()
            except ssl.SSLWantReadError:
                pass
        for source, destination in ((co, si), (so, ci)):
            if source.pending:
                destination.write(source.read())
        if c.version() and s.version():
            if c.version() != 'TLSv1.3':
                raise RuntimeError('wrong fixture transport')
            return
    raise RuntimeError('offline handshake incomplete')
handshake('ca.pem', '127.0.0.1')
for ca, hostname in (('other-ca.pem', '127.0.0.1'), ('ca.pem', 'wrong.invalid')):
    try:
        handshake(ca, hostname)
    except ssl.SSLCertVerificationError:
        continue
    raise RuntimeError('untrusted fixture accepted')
`, dir)
	// Never print generated certificates, keys or subprocess diagnostics.
	if cmd.Run() != nil {
		t.Fatal("Python rejected the trusted fixture or accepted a wrong CA/hostname")
	}
}
