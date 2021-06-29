// Package sct verifies Signed Certificate Timestamp in TLS connections.
// See [RFC 6962](https://datatracker.ietf.org/doc/rfc6962/).
package sct

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist2"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	//zocsp "github.com/zzylydx/zcrypto/x509/revocation/ocsp"
)

var (
	defaultCheckerOnce sync.Once
	defaultChecker     *checker
)

// checker performs SCT checks.
type checker struct {
	ll *loglist2.LogList
}

// getDefaultChecker returns the default Checker, initializing it if needed.
func GetDefaultChecker() *checker {
	defaultCheckerOnce.Do(func() {
		defaultChecker = &checker{
			ll: newDefaultLogList(),
		}
	})

	return defaultChecker
}

// CheckConnectionState examines SCTs (both embedded and in the TLS extension) and returns
// nil if at least one of them is valid.
func CheckConnectionState(state *tls.ConnectionState) error {
	return GetDefaultChecker().checkConnectionState(state)
}

func (c *checker) checkConnectionState(state *tls.ConnectionState) error {
	if state == nil {
		return errors.New("no TLS connection state")
	}

	if len(state.PeerCertificates) == 0 {
		return errors.New("no peer certificates in TLS connection state")
	}

	chain, err := buildCertificateChain(state.PeerCertificates) // 构建证书链
	if err != nil {
		return err
	}

	lastError := errors.New("no Signed Certificate Timestamps found")

	// SCTs provided in the TLS handshake.
	if err = c.checkTLSSCTs(state.SignedCertificateTimestamps, chain); err != nil {
		lastError = err
	} else {
		return nil
	}

	// Check SCTs embedded in the leaf certificate.
	if err = c.checkCertSCTs(chain); err != nil {
		lastError = err
	} else {
		return nil
	}

	// TODO(mberhault): check SCTs in OSCP response.
	// OcspStapling sct verify
	// ocsp和tls方式一样
	//ocspResponse, err := zocsp.ConvertResponse(string(state.OCSPResponse))
	//if err != nil {
	//	return nil
	//}
	//var sctListByte [][]byte
	//sctListByte, err = zocsp.ParseSCTListFromOcspResponseByte(ocspResponse)
	//if err = c.checkOcspSCTs(sctListByte, chain); err != nil {
	//	lastError = err
	//} else {
	//	return nil
	//}
	//
	return lastError
}

// Check SCTs provided with the TLS handshake. Returns an error if no SCT is valid.
func (c *checker) checkTLSSCTs(scts [][]byte, chain []*ctx509.Certificate) error {
	if len(scts) == 0 {
		return errors.New("no SCTs in SSL handshake")
	}

	merkleLeaf, err := ct.MerkleTreeLeafFromChain(chain, ct.X509LogEntryType, 0)
	if err != nil {
		return err
	}

	for _, sct := range scts {
		x509SCT := &ctx509.SerializedSCT{Val: sct}
		err := c.checkOneSCT(x509SCT, merkleLeaf)
		if err == nil {
			// Valid: return early.
			return nil
		}
	}

	return errors.New("no valid SCT in SSL handshake")
}

// Check SCTs embedded in the leaf certificate. Returns an error if no SCT is valid.
func (c *checker) checkCertSCTs(chain []*ctx509.Certificate) error {
	leaf := chain[0]
	if len(leaf.SCTList.SCTList) == 0 {
		return errors.New("no SCTs in leaf certificate")
	}

	if len(chain) < 2 {
		// TODO(mberhault): optionally fetch issuer from IssuingCertificateURL.
		return errors.New("no issuer certificate in chain")
	}
	issuer := chain[1]

	merkleLeaf, err := ct.MerkleTreeLeafForEmbeddedSCT([]*ctx509.Certificate{leaf, issuer}, 0)
	if err != nil {
		return err
	}

	for _, sct := range leaf.SCTList.SCTList {
		err := c.checkOneSCT(&sct, merkleLeaf)
		if err == nil {
			// Valid: return early.
			return nil
		}
	}

	return errors.New("no valid SCT in SSL handshake")
}

// Check SCTs provided with the TLS handshake. Returns an error if no SCT is valid.
func (c *checker) checkOcspSCTs(scts [][]byte, chain []*ctx509.Certificate) error {
	merkleLeaf, err := ct.MerkleTreeLeafFromChain(chain, ct.X509LogEntryType, 0)
	if err != nil {
		return err
	}

	for _, sct := range scts {
		x509SCT := &ctx509.SerializedSCT{Val: sct}
		err := c.checkOneSCT(x509SCT, merkleLeaf)
		if err == nil {
			// Valid: return early.
			return nil
		}
	}

	return errors.New("no valid SCT in SSL handshake")
}

func (c *checker) checkOneSCT(x509SCT *ctx509.SerializedSCT, merkleLeaf *ct.MerkleTreeLeaf) error {
	sct, err := ctx509util.ExtractSCT(x509SCT) // 反序列化sct
	if err != nil {
		return err
	}

	ctLog := c.ll.FindLogByKeyHash(sct.LogID.KeyID) // 找到对应的ct log
	if ctLog == nil {
		return fmt.Errorf("no log found with KeyID %x", sct.LogID)
	}

	logInfo, err := newLogInfoFromLog(ctLog)
	if err != nil {
		return fmt.Errorf("could not create client for log %s", ctLog.Description) // 不懂
	}

	err = logInfo.VerifySCTSignature(*sct, *merkleLeaf) // 验证签名
	if err != nil {
		return err
	}

	_, err = logInfo.VerifyInclusion(context.Background(), *merkleLeaf, sct.Timestamp)
	if err != nil {
		age := time.Since(ct.TimestampToTime(sct.Timestamp))
		if age >= logInfo.MMD {
			return fmt.Errorf("failed to verify inclusion in log %q", ctLog.Description)
		}

		// TODO(mberhault): option to fail on timestamp too recent.
		return nil
	}

	return nil
}

// use for webemail measurement, only check sct validity. true or false
// Check SCTs provided with the TLS handshake. Returns an error if no SCT is valid.
func (c *checker) VerifyTLSSCTs(sct []byte, chain []*ctx509.Certificate) bool {
	merkleLeaf, err := ct.MerkleTreeLeafFromChain(chain, ct.X509LogEntryType, 0)
	if err != nil {
		return false
	}

	x509SCT := &ctx509.SerializedSCT{Val: sct}
	err = c.checkOneSCT(x509SCT, merkleLeaf)
	if err != nil {
		// Valid: return early.
		return false
	}

	return true
}

// Check SCTs embedded in the leaf certificate. Returns an error if no SCT is valid.
func (c *checker) VerifyCertSCTs(sct *ctx509.SerializedSCT, chain []*ctx509.Certificate) bool {
	leaf := chain[0]
	if len(leaf.SCTList.SCTList) == 0 {
		return false
	}

	if len(chain) < 2 {
		// TODO(mberhault): optionally fetch issuer from IssuingCertificateURL.
		return false
	}
	issuer := chain[1]

	merkleLeaf, err := ct.MerkleTreeLeafForEmbeddedSCT([]*ctx509.Certificate{leaf, issuer}, 0)
	if err != nil {
		return false
	}

	err = c.checkOneSCT(sct, merkleLeaf)
	if err != nil {
		return false
	}

	return true
}

// Check SCTs provided with the TLS handshake. Returns an error if no SCT is valid.
func (c *checker) VerifyOcspSCTs(sct []byte, chain []*ctx509.Certificate) bool {
	merkleLeaf, err := ct.MerkleTreeLeafFromChain(chain, ct.X509LogEntryType, 0)
	if err != nil {
		return false
	}

	x509SCT := &ctx509.SerializedSCT{Val: sct}
	err = c.checkOneSCT(x509SCT, merkleLeaf)
	if err != nil {
		return false
	}

	return true
}

