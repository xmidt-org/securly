// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errUnknown = fmt.Errorf("unknown error")

var chainA = mustGeneratecertChain(
	`leaf
		<-ica(1.2.900,1.2.901)
		<-ica(1.2.100)
		<-root`)

var chainB = mustGeneratecertChain(
	`leaf
		<-ica(1.2.900,1.2.901)
		<-ica(1.2.100)
		<-root`)

type certChain struct {
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey

	chain []*x509.Certificate // includes the leaf but not the root

	root *x509.Certificate
}

// generateCertChain generates a certificate chain with the given description.
// The description is a string that describes the chain in the following format:
// leaf<-ica(1.2.900,1.2.901)<-ica(1.2.100)<-root
// The chain is generated in the order of root, ica(1.2.100), ica(1.2.900, 1.2.901), leaf.
// The root certificate is self-signed and the rest are signed by the previous certificate in the chain.
// The leaf certificate is signed by the last ica in the chain.
// The policies are added to the certificate as Extended Key Usages.
// The private key of the leaf certificate is also returned.
// The chain is returned as a slice of x509.Certificate.
func generateCertChain(desc string) ([]*x509.Certificate, *ecdsa.PrivateKey, error) {
	re := regexp.MustCompile(`\s+`)
	desc = re.ReplaceAllString(desc, "")

	nodes := strings.Split(desc, "<-")
	certs := make([]*x509.Certificate, len(nodes))

	var parentCert *x509.Certificate
	var parentKey *ecdsa.PrivateKey

	for i := len(nodes) - 1; i >= 0; i-- {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject: pkix.Name{
				Organization: []string{fmt.Sprintf("Intermediate %d", len(nodes)-1-i)},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IsCA:                  i != 0, // Only the root and intermediate CAs are CAs
			BasicConstraintsValid: true,
		}

		// RootCA
		if i == len(nodes)-1 {
			template.Subject = pkix.Name{
				Organization: []string{"Root"},
			}
		}

		// Leaf Node
		if i == 0 {
			template.Subject = pkix.Name{
				Organization: []string{"Leaf"},
			}
			template.KeyUsage = x509.KeyUsageDigitalSignature
			template.IsCA = false
		}

		// Add policies as OIDs
		if i != 0 {
			policies := strings.TrimPrefix(strings.TrimSuffix(nodes[i], ")"), "ica(")
			if policies != nodes[i] {
				for _, policy := range strings.Split(policies, ",") {
					oid := asn1.ObjectIdentifier{}
					for _, part := range strings.Split(policy, ".") {
						var num int
						_, err := fmt.Sscanf(part, "%d", &num)
						if err != nil {
							return nil, nil, fmt.Errorf("invalid policy OID: %v", policy)
						}
						oid = append(oid, num)
					}
					template.PolicyIdentifiers = append(template.PolicyIdentifiers, oid)
				}
			}
		}

		var certDER []byte
		if parentCert == nil {
			certDER, err = x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		} else {
			certDER, err = x509.CreateCertificate(rand.Reader, template, parentCert, &priv.PublicKey, parentKey)
		}
		if err != nil {
			return nil, nil, err
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, nil, err
		}

		certs[i] = cert
		parentCert = cert
		parentKey = priv
	}

	leafKey := parentKey

	return certs, leafKey, nil
}

// TestGenerateCertChain tests the generateCertChain function.
func TestGenerateCertChain(t *testing.T) {
	tests := []struct {
		desc     string
		expected []string
	}{
		{
			desc:     "leaf<-ica(1.2.900,1.2.901)<-ica(1.2.100)<-root",
			expected: []string{"Leaf", "Intermediate 2", "Intermediate 1", "Root"},
		},
		{
			desc:     "leaf<-ica(1.2.100)<-root",
			expected: []string{"Leaf", "Intermediate 1", "Root"},
		},
		{
			desc: `leaf<-
						ica(1.2.100) <-ica
							<-ica
							<-ica<-
							root`,
			expected: []string{"Leaf", "Intermediate 4", "Intermediate 3", "Intermediate 2", "Intermediate 1", "Root"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			certs, _, err := generateCertChain(tt.desc)
			require.NoError(err)

			assert.Equal(len(tt.expected), len(certs))

			for i, cert := range certs {
				assert.Equal(tt.expected[i], cert.Subject.Organization[0])
			}

			re := regexp.MustCompile(`\s+`)
			desc := re.ReplaceAllString(tt.desc, "")

			// Verify policies
			for i, node := range strings.Split(desc, "<-") {
				if strings.Contains(node, "ica(") {
					policies := strings.TrimPrefix(strings.TrimSuffix(node, ")"), "ica(")
					for _, policy := range strings.Split(policies, ",") {
						oid := asn1.ObjectIdentifier{}
						for _, part := range strings.Split(policy, ".") {
							var num int
							n, err := fmt.Sscanf(part, "%d", &num)
							require.NoError(err)
							require.Equal(1, n)
							oid = append(oid, num)
						}

						found := false
						for _, certPolicy := range certs[i].PolicyIdentifiers {
							if certPolicy.Equal(oid) {
								found = true
								break
							}
						}
						if !found {
							t.Errorf("expected policy %v in certificate %d, but not found", oid, i)
						}
					}
				}
			}
		})
	}
}

func mustGeneratecertChain(desc string) certChain {
	certs, key, err := generateCertChain(desc)
	if err != nil {
		panic(err)
	}

	return certChain{
		leaf:    certs[0],
		leafKey: key,
		chain:   certs[:len(certs)-1],
		root:    certs[len(certs)-1],
	}
}

func TestMustGenerateChain(t *testing.T) {
	got := mustGeneratecertChain("leaf<-ica(1.2.900,1.2.901)<-ica(1.2.100)<-root")

	assert := assert.New(t)
	require := require.New(t)

	require.NotNil(got)

	require.NotNil(got.leaf)
	require.NotNil(got.leafKey)
	require.NotNil(got.chain)
	require.NotNil(got.root)

	assert.Equal("Leaf", got.leaf.Subject.Organization[0])

	require.Len(got.chain, 3)
	assert.Equal("Leaf", got.chain[0].Subject.Organization[0])
	assert.Equal("Intermediate 2", got.chain[1].Subject.Organization[0])
	assert.Equal("Intermediate 1", got.chain[2].Subject.Organization[0])

	assert.Equal("Root", got.root.Subject.Organization[0])
}

func mustGenerateResponse(alg jwa.KeyEncryptionAlgorithm, c *x509.Certificate) *Encryption {
	rv := Encryption{
		Alg: alg,
		Key: mustFromRaw(c.PublicKey),
	}

	return &rv
}

func mustFromRaw(a any) jwk.Key {
	k, err := jwk.FromRaw(a)
	if err != nil {
		panic(err)
	}
	return k
}
