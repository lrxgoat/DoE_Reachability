package check

import (
	"Block_Check/metrics"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	_ "github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"io"
	"strings"
	"time"
)

func DoQ_Verify(Target *metrics.Result, sni, iptype string) (bool, string, string) {
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

	// 打开QUIC会话
	openStreamCtx, openStreamCancel := context.WithTimeout(context.Background(), timeout)
	defer openStreamCancel()
	stream, openerr := quicSeeion.OpenStreamSync(openStreamCtx)
	if openerr != nil {
		return false, metrics.WriteResult(Target, "QUIC", openerr.Error()) + "\n", certResult
	}

	// When sending queries over a QUIC connection, the DNS Message ID MUST
	// be set to zero.  The stream mapping for DoQ allows for unambiguous
	// correlation of queries and responses and so the Message ID field is
	// not required.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-12#section-5.2.1
	req := metrics.Raw_dns_query(Target)
	req.Id = 0
	reqbuf, _ := req.Pack()

	// 发送DoQ查询
	_, doqerr := stream.Write(reqbuf)
	if doqerr != nil {
		return false, metrics.WriteResult(Target, "Response", "Write: "+doqerr.Error()) + "\n", certResult
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-12#section-5.2
	_ = stream.Close()

	respBuf, err := io.ReadAll(stream)
	if err != nil {
		return false, metrics.WriteResult(Target, "Response", "Read: "+err.Error()) + "\n", certResult
	}

	reply := dns.Msg{}
	err = reply.Unpack(respBuf)
	if err != nil {
		return false, metrics.WriteResult(Target, "Response", "Result: "+err.Error()) + "\n", certResult
	}

	check_flag, dns_answer, check_err := metrics.DNS_answer_check(&reply)
	Target.DoEQueryResult = dns_answer
	if check_flag {
		return true, metrics.WriteResult(Target, "Success", "None") + "\n", certResult
	} else {
		return false, metrics.WriteResult(Target, "Response", "Result: "+check_err) + "\n", certResult
	}

}
