package check

import (
	"Block_Check/metrics"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/miekg/dns"
	"strings"
	"time"
)

const timeout = 10 * time.Second

func DoT_Verify(Target *metrics.Result, sni, iptype string) (bool, string, string) {
	var certResult string
	// 发送ICMP数据包
	pingFlag, pingResult := metrics.PingTest(Target.ServerIp, Target.IpType)
	if pingFlag {
		Target.ICMPRtt = pingResult
	} else {
		return false, metrics.WriteResult(Target, "Ping", pingResult) + "\n", certResult
	}

	// 建立TCP连接
	tcpconn, tcperr := metrics.TCP_conn(Target.ServerIp, Target.ScanPort, iptype)
	if tcperr != "" {
		return false, metrics.WriteResult(Target, "TCP", tcperr) + "\n", certResult
	}

	// 建立TLS连接
	tlsConn, tlserr := metrics.TLS_conn(Target.ServerDomain, sni, tcpconn)
	if tlserr != "" {
		return false, metrics.WriteResult(Target, "TLS", tlserr) + "\n", certResult
	}

	Target.TLSVersion = metrics.TLSVerDict[tlsConn.ConnectionState().Version]

	// 检查证书
	certChian := tlsConn.ConnectionState().PeerCertificates

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
		for _, cert := range tlsConn.ConnectionState().PeerCertificates {
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

		return false, metrics.WriteResult(Target, "TLS", "Cert Err") + "\n", certResult
	}

	// 发送DoT查询
	cn := dns.Conn{Conn: tlsConn}
	_ = cn.SetDeadline(time.Now().Add(timeout))

	dnserr := cn.WriteMsg(metrics.Raw_dns_query(Target))
	if dnserr != nil {
		return false, metrics.WriteResult(Target, "Response", "Write: "+dnserr.Error()) + "\n", certResult
	}

	reply, queryerr := cn.ReadMsg()
	if queryerr != nil {
		return false, metrics.WriteResult(Target, "Response", "Read: "+queryerr.Error()) + "\n", certResult
	}

	// 解析DoT响应
	check_flag, dns_answer, check_err := metrics.DNS_answer_check(reply)
	Target.DoEQueryResult = dns_answer

	if check_flag {
		return true, metrics.WriteResult(Target, "Success", "None") + "\n", certResult
	} else {
		return false, metrics.WriteResult(Target, "Response", "Result: "+check_err) + "\n", certResult
	}

}
