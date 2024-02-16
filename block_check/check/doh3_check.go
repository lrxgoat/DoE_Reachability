package check

import (
	"Block_Check/metrics"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	_ "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
	"io"
	"net/http"
	"strings"
	"time"
)

func DoH3_Verify(Target *metrics.Result, sni, iptype, httpMethod string) (bool, string, string) {
	var certResult string
	// 发送ICMP数据包
	pingFlag, pingResult := metrics.PingTest(Target.ServerIp, Target.IpType)
	if pingFlag {
		Target.ICMPRtt = pingResult
	} else {
		return false, metrics.WriteResult(Target, "Ping", pingResult) + "\n", certResult
	}

	// 发送quic版本协商测试
	quicpingFlag, quicpingResult := metrics.QUICPing(Target.ServerIp, Target.ScanPort, iptype)
	if quicpingFlag {
		Target.QUICVNResult = quicpingResult
	} else {
		return false, metrics.WriteResult(Target, "QUIC-VN", quicpingResult) + "\n", certResult

	}

	// 建立QUIC连接
	quicSeeion, quicerr := metrics.QUIC_conn(Target.ServerIp, Target.ServerDomain, Target.ScanPort, Target.IpType, sni)
	if quicerr != "" {
		return false, metrics.WriteResult(Target, "QUIC", quicerr) + "\n", certResult
	}

	Target.TLSVersion = metrics.TLSVerDict[quicSeeion.ConnectionState().TLS.Version]

	// 检查证书
	certChian := quicSeeion.ConnectionState().TLS.PeerCertificates

	Target.CertBefore = certChian[0].NotBefore.Format(time.RFC3339)
	Target.CerAfter = certChian[0].NotAfter.Format(time.RFC3339)
	Target.CertLife = certChian[0].NotAfter.Sub(certChian[0].NotBefore).Hours() / 24
	Target.CertCN = certChian[0].Subject.CommonName
	Target.CertSAN = certChian[0].DNSNames
	if len(certChian[0].Issuer.Organization) > 0 {
		Target.CertCA = certChian[0].Issuer.Organization[0] + ";" + certChian[0].Issuer.CommonName
	}

	certvalid, certerr := metrics.CheckCertsChain(certChian, Target.ServerDomain, sni)
	Target.CertValid = certvalid
	Target.CertErr = certerr

	if !Target.CertValid {
		// 保存证书链
		certchain := ""
		for _, cert := range quicSeeion.ConnectionState().TLS.PeerCertificates {
			var block = &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}

			aa := pem.EncodeToMemory(block)
			enc := base64.StdEncoding.EncodeToString(aa)
			certchain = certchain + "###" + enc // 分隔符 ","
		}
		tempCertTarget := new(metrics.CertResult)
		tempCertTarget.ServerIp = Target.ServerIp
		tempCertTarget.ServerDomain = Target.ServerDomain
		tempCertTarget.ScanType = Target.ScanType
		tempCertTarget.IpType = iptype
		tempCertTarget.CertChainRaw = strings.TrimLeft(certchain, "###")
		tempCertTarget.CheckTime = Target.CheckTime
		tempCertTarget.VPNServer = Target.VPNServer
		//tempCertTarget.CertChainHash = metrics.CertSha256(tempCertTarget.CertChainRaw)

		//Target.CertChainHash = metrics.CertSha256(tempCertTarget.CertChainRaw)

		tempResult, _ := json.Marshal(tempCertTarget)
		certResult = string(tempResult) + "\n"

		return false, metrics.WriteResult(Target, "QUIC", "Cert Err") + "\n", certResult
	}

	var httpreq *http.Request
	var httperr error
	httpbuf, _ := metrics.Raw_dns_query(Target).Pack()
	// 指定HTTP请求方法
	var http_host string
	if iptype == "ipv4" {
		http_host = Target.ServerIp + ":" + Target.ScanPort
	} else {
		http_host = "[" + Target.ServerIp + "]" + ":" + Target.ScanPort
	}

	if httpMethod == "POST" {
		PostBody := bytes.NewReader(httpbuf)
		server_url := "https://" + http_host + "/" + Target.HTTPPath
		httpreq, httperr = http.NewRequest(http.MethodPost, server_url, PostBody)
		if httperr != nil {
			return false, metrics.WriteResult(Target, "Response", "Request: "+httperr.Error()) + "\n", certResult
		}
	} else {
		server_url := "https://" + http_host + "/" + Target.HTTPPath + "?dns=" + base64.RawURLEncoding.EncodeToString(httpbuf)
		httpreq, httperr = http.NewRequest(http.MethodGet, server_url, nil)
		if httperr != nil {
			return false, metrics.WriteResult(Target, "Response", "Request: "+httperr.Error()) + "\n", certResult
		}
	}

	httpreq.Header.Set("Content-Type", DohDnsType)
	if sni == "true" {
		httpreq.Host = Target.ServerDomain // Set the Host header to the domain name
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         Target.ServerDomain,
		NextProtos:         []string{"h3", "h3-29"},
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}

	h3Client := http.Client{
		Timeout: timeout,
		Transport: &http3.RoundTripper{
			TLSClientConfig: tlsCfg,
			//Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			//	return quicSeeion, nil
			//},
		},
	}

	resp, http3err := h3Client.Do(httpreq)
	if http3err != nil {
		return false, metrics.WriteResult(Target, "Response", "Conn: "+http3err.Error()) + "\n", certResult
	}

	Target.HTTPStatus = resp.StatusCode
	//Target.PageHeader = metrics.FormatHeader(resp.Header)

	// 解析DoH3响应
	if resp == nil {
		return false, metrics.WriteResult(Target, "Response", "Result: Response None") + "\n", certResult

	} else {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		dnsresponse := dns.Msg{}
		dnsresponse.Unpack(bodyBytes)

		check_flag, dns_answer, check_err := metrics.DNS_answer_check(&dnsresponse)
		Target.DoEQueryResult = dns_answer

		if check_flag {
			return true, metrics.WriteResult(Target, "Success", "None") + "\n", certResult
		} else {
			return false, metrics.WriteResult(Target, "Response", "Result: "+check_err) + "\n", certResult
		}
	}

}
