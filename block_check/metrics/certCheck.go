package metrics

import "crypto/x509"
import _ "crypto/tls"
import "github.com/certifi/gocertifi"

// 验证域名的证书链，参考 https://golang.org/src/crypto/x509/verify.go 以及 https://gist.github.com/devtdeng/4f6adcb5a306f2ae035a2e7d9f724d17
func CheckCertsChain(Certchain []*x509.Certificate, domain, sni string) (bool, string) {
	// get Mozilla Root CA Certificates
	roots, _ := gocertifi.CACerts()
	// certNumber
	certNum := len(Certchain)
	// 分情况
	if certNum == 0 {
		return false, "certNum is 0"
	}
	if certNum == 1 {
		// leafcert
		leafCert := Certchain[0]
		// config
		if sni == "true" {
			opts := x509.VerifyOptions{
				DNSName: domain,
				Roots:   roots,
			}
			if _, err := leafCert.Verify(opts); err != nil {
				return false, err.Error()
			}
		} else {
			opts := x509.VerifyOptions{
				//DNSName: domain,
				Roots: roots,
			}
			if _, err := leafCert.Verify(opts); err != nil {
				return false, err.Error()
			}
		}

	} else {
		// leafcert
		leafCert := Certchain[0]
		// inter certs
		inter := x509.NewCertPool()
		for _, cert := range Certchain[1:] {
			inter.AddCert(cert)
		}
		// config
		if sni == "true" {
			opts := x509.VerifyOptions{
				DNSName:       domain,
				Roots:         roots,
				Intermediates: inter,
			}
			if _, err := leafCert.Verify(opts); err != nil {
				return false, err.Error()
			}
		} else {
			opts := x509.VerifyOptions{
				//DNSName: domain,
				Roots:         roots,
				Intermediates: inter,
			}
			if _, err := leafCert.Verify(opts); err != nil {
				return false, err.Error()
			}
		}

	}

	return true, ""
}
