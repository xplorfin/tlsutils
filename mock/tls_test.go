package mock

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/xplorfin/tlsutils"
	"io/ioutil"
	"testing"
)

func TestTemporaryCert(t *testing.T) {
	tmpCertFile, tmpKeyFile := TemporaryCert(t)
	pub, err := ioutil.ReadFile(tmpCertFile)
	if err != nil {
		t.Error(err)
	}

	priv, err := ioutil.ReadFile(tmpKeyFile)
	if err != nil {
		t.Error(err)
	}

	derivedCert := tlsutils.TlsCert{
		PublicKey:  string(pub),
		PrivateKey: string(priv),
	}
	isValid, err := tlsutils.VerifyCertificate(derivedCert)
	if err != nil {
		t.Error(err)
	}

	if !isValid {
		t.Errorf("expected cert to be valid")
	}
}

func TestTemporaryCertInChain(t *testing.T) {
	chainLoc, serverLoc, keyFile := TemporaryCertInChain(t)
	_ = keyFile
	chainFile, err := ioutil.ReadFile(chainLoc)
	if err != nil {
		t.Error(err)
	}

	serverFile, err := ioutil.ReadFile(serverLoc)
	if err != nil {
		t.Error(err)
	}
	block, _ := pem.Decode(chainFile)
	chain, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Error(err)
	}
	block, _ = pem.Decode(serverFile)
	server, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Error(err)
	}
	isValid, err := tlsutils.VerifyLowNoDca(chain, server)
	if !isValid {
		t.Error(err)
	}
}
