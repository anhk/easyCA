package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/anhk/easyCA/gopass"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

type KeyPair struct {
	priv interface{}
	pub  interface{}
	cert *x509.Certificate
}

func (k *KeyPair) GenerateRsaKey() (err error) {
	k.priv, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	k.pub = &k.priv.(*rsa.PrivateKey).PublicKey
	return nil
}

func (k *KeyPair) GenerateEccKey() (err error) {
	k.priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	k.pub = &k.priv.(*ecdsa.PrivateKey).PublicKey
	return nil
}

func (k *KeyPair) GenerateKey(algo string) error {
	switch algo {
	case "rsa":
		k.GenerateRsaKey()
	case "ecc":
		k.GenerateEccKey()
	default:
		return errors.New("Invalid algo, only support `rsa` and `ecc`.")
	}
	return nil
}

func (k *KeyPair) WriteEccPrivateKey(path, password string) (err error) {
	r, ok := k.priv.(*ecdsa.PrivateKey)
	if ok != true {
		return errors.New("Invalid format.")
	}

	b, err := x509.MarshalECPrivateKey(r)
	if err != nil {
		return err
	}

	certOut, err := os.Create(path)
	if err != nil {
		return err
	}
	defer certOut.Close()

	prime256v1, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err := pem.Encode(certOut, &pem.Block{Type: "EC PARAMETERS", Bytes: prime256v1}); err != nil {
		return err
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		return err
	}
	/**	if password != "" {
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return err
		}
	}**/
	return nil
}

func (k *KeyPair) WritePkcs1PrivateKey(path, password string) (err error) {
	r, ok := k.priv.(*rsa.PrivateKey)
	if ok != true {
		return errors.New("Invalid format.")
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(r)}
	if password != "" {
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return err
		}
	}
	ioutil.WriteFile(path, pem.EncodeToMemory(block), 0644)
	return nil
}

func (k *KeyPair) WritePkcs8PrivateKey(path, password string) error {
	b, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: b}
	if password != "" {
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return err
		}
	}
	ioutil.WriteFile(path, pem.EncodeToMemory(block), 0644)
	return nil
}

func (k *KeyPair) WritePrivateKey(path, password string, format string) error {
	switch format {
	case "pkcs1":
		switch k.priv.(type) {
		case *rsa.PrivateKey:
			return k.WritePkcs1PrivateKey(path, password)
		case *ecdsa.PrivateKey:
			return k.WriteEccPrivateKey(path, password)
		}
	case "pkcs8":
		return k.WritePkcs8PrivateKey(path, password)
	default:
		return errors.New("Invalid format, only support `pkcs1` and `pkcs8`.")
	}
	return nil
}

func (k *KeyPair) WriteCertificate(path string) error {
	ioutil.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.cert.Raw}), 0644)
	return nil
}

func (k *KeyPair) LoadPrivateKey(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return fmt.Errorf("Invalid PrivateKey file: %s", path)
	}

	if x509.IsEncryptedPEMBlock(block) {
		passWord, err := gopass.GetPass("Enter Key Passphrase for " + path + ": ")
		if err != nil {
			return err
		}
		if blockDer, err := x509.DecryptPEMBlock(block, []byte(passWord)); err != nil {
			return err
		} else {
			block.Bytes = blockDer
		}
	}

	k.priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		k.pub = &k.priv.(*rsa.PrivateKey).PublicKey
		return nil
	}

	if privKeyPkcs8, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		k.priv = privKeyPkcs8.(*rsa.PrivateKey)
		k.pub = &k.priv.(*ecdsa.PrivateKey).PublicKey
		return nil
	}

	return errors.New("not supported yet.")
}

func (k *KeyPair) LoadCertificate(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(content)
	if block == nil {
		return fmt.Errorf("Invalid Certificate file: %s", path)
	}

	if k.cert, err = x509.ParseCertificate(block.Bytes); err != nil {
		return err
	}
	return nil
}

func GenerateSelfSignedCertificate(algo string, isCA bool, sCN string, days int) (*KeyPair, error) {
	var err error
	k := &KeyPair{}

	if err = k.GenerateKey(algo); err != nil {
		return nil, err
	}

	template, err := makeTemplate(isCA, sCN, days)
	if err != nil {
		return nil, err
	}

	if sCN != "" {
		template.DNSNames = append(template.DNSNames, sCN)
	}

	certBlob, err := x509.CreateCertificate(rand.Reader, template, template, k.pub, k.priv)
	if err != nil {
		return nil, err
	}
	k.cert, err = x509.ParseCertificate(certBlob)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func GenerateCASignedCertificate(algo string, sCN string, ca *KeyPair, days int) (*KeyPair, error) {
	var err error
	k := &KeyPair{}

	if err = k.GenerateKey(algo); err != nil {
		return nil, err
	}

	template, err := makeTemplate(false, sCN, days)
	if err != nil {
		return nil, err
	}

	if sCN != "" {
		template.DNSNames = append(template.DNSNames, sCN)
	}

	certBlob, err := x509.CreateCertificate(rand.Reader, template, ca.cert, k.pub, ca.priv)
	if err != nil {
		return nil, err
	}
	k.cert, err = x509.ParseCertificate(certBlob)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func makeTemplate(isCA bool, sCN string, days int) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(0xffffffff))
	if err != nil {
		return nil, err
	}
	subjectKeyId := make([]byte, 16)
	if _, err = rand.Read(subjectKeyId); err != nil {
		return nil, err
	}
	return &x509.Certificate{
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		SubjectKeyId:          subjectKeyId,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName:   sCN,
			Country:      []string{"CN"},
			Organization: []string{"JDCloud Inc."},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, days),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
	}, nil
}
