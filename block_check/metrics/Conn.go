package metrics

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"golang.org/x/net/html"
	"math/rand"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ICMP 数据包结构体
type ICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
}

var BaseQueryDomain = "doe.dnsavailable.xyz"

var DefaultQUICVersions = []quic.VersionNumber{
	quic.Version1,
	quic.VersionDraft29,
}
var defaultDoQVersions = []string{"doq", "doq-i00", "doq-i02", "dq", "doq-i11", "h3", "h3-29"}

const timeout = 10 * time.Second

var Ipv4BogonList = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "127.0.53.53/32", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"}

var Ipv6BogonList = []string{"::/128", "::1/128", "::ffff:0:0/96", "::/96", "100::/64", "2001:10::/28",
	"2001:db8::/32", "FC00::/7", "fe80::/10", "fec0::/10", "ff00::/8", "2002::/24", "2002:a00::/24",
	"2002:7f00::/24", "2002:a9fe::/32", "2002:ac10::/28", "2002:c000::/40", "2002:c000:200::/40", "2002:c0a8::/32",
	"2002:c612::/31", "2002:c633:6400::/40", "2002:cb00:7100::/40", "2002:e000::/20", "2002:f000::/20", "2002:ffff:ffff::/48",
	"2001::/40", "2001:0:a00::/40", "2001:0:7f00::/40", "2001:0:a9fe::/48", "2001:0:ac10::/44", "2001:0:c000::/56",
	"2001:0:c000:200::/56", "2001:0:c0a8::/48", "2001:0:c612::/47", "2001:0:c633:6400::/56", "2001:0:cb00:7100::/56",
	"2001:0:e000::/36", "2001:0:f000::/36", "2001:0:ffff:ffff::/64"}

// IsIPBogon 检查IPv4地址是否在 bogon列表中。是返回true，不是返回false
func IsIPBogon(ipStr string, iptype string) bool {
	ip := net.ParseIP(ipStr)
	if iptype == "ipv4" {
		for i := 0; i < len(Ipv4BogonList); i++ {
			_, cidr, _ := net.ParseCIDR(Ipv4BogonList[i])

			if cidr.Contains(ip) {
				return true
			}
		}
	} else if iptype == "ipv6" {
		for i := 0; i < len(Ipv6BogonList); i++ {
			_, cidr, _ := net.ParseCIDR(Ipv6BogonList[i])

			if cidr.Contains(ip) {
				return true
			}
		}
	}

	return false
}

func Raw_dns_query(Target *Result) *dns.Msg {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true

	rand.Seed(time.Now().UnixNano())
	// 生成四位随机数
	randNum := rand.Intn(10000) + 80000
	// 将随机数转换为字符串
	randStr := strings.Replace(Target.ServerDomain, ".", "-", -1) + "_" +
		strings.Replace(Target.VPNConfig, ".", "-", -1) + "_" +
		strconv.Itoa(randNum)

	Target.QueryDomain = randStr + "." + BaseQueryDomain

	req.Question = []dns.Question{
		{Name: Target.QueryDomain + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	return &req
}

func TCP_conn(ip, port, iptype string) (*net.Conn, string) {

	// 建立tcp连接
	var tcpconn net.Conn
	var tcperr error
	dialer := net.Dialer{Timeout: timeout}
	if iptype == "ipv4" {
		fullAddr := ip + ":" + port
		tcpconn, tcperr = dialer.Dial("tcp", fullAddr)
	} else {
		fullAddr := "[" + ip + "]" + ":" + port
		tcpconn, tcperr = dialer.Dial("tcp6", fullAddr)
	}
	if tcperr != nil {
		return &tcpconn, tcperr.(*net.OpError).Err.Error()
	} else {
		return &tcpconn, ""
	}
}

func UDP_conn(ip, port, iptype string) (net.Conn, string) {

	// 建立udp连接
	var udpconn net.Conn
	var udperr error
	dialer := net.Dialer{Timeout: timeout}
	if iptype == "ipv4" {
		fullAddr := ip + ":" + port
		udpconn, udperr = dialer.Dial("udp", fullAddr)
	} else {
		fullAddr := "[" + ip + "]" + ":" + port
		udpconn, udperr = dialer.Dial("udp6", fullAddr)
	}
	if udperr != nil {
		return udpconn, udperr.(*net.OpError).Err.Error()
	} else {
		return udpconn, ""
	}
}

func TLS_conn(domain, sni string, tcpconn *net.Conn) (*tls.Conn, string) {
	// 建立TLS连接
	var tlsConfig *tls.Config
	if sni == "true" {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}
	}

	tlsConn := tls.Client(*tcpconn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	tlserr := tlsConn.Handshake()

	if tlserr != nil {
		tlsErr := tlserr.Error()
		if strings.Contains(tlserr.Error(), "timeout") {
			tlsErr = "timeout"
		} else if strings.Contains(tlserr.Error(), "reset by peer") {
			tlsErr = "peer_reset"
		}
		return tlsConn, tlsErr
	} else {
		return tlsConn, ""
	}

}

func QUIC_conn(ip, domain, port, iptype, sni string) (quic.Connection, string) {
	quicCfg := &quic.Config{
		HandshakeIdleTimeout: timeout,
		Versions:             DefaultQUICVersions,
	}

	var tlsConfig *tls.Config
	if sni == "true" {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
			NextProtos:         defaultDoQVersions,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         defaultDoQVersions,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), timeout)
	defer dialCancel()

	var quicsession quic.Connection
	var quicerr error

	if iptype == "ipv4" {
		fullAddr := ip + ":" + port
		quicsession, quicerr = quic.DialAddrContext(dialCtx, fullAddr, tlsConfig, quicCfg)
	} else {
		fullAddr := "[" + ip + "]" + ":" + port
		quicsession, quicerr = quic.DialAddrContext(dialCtx, fullAddr, tlsConfig, quicCfg)
	}

	if quicerr != nil {
		return quicsession, quicerr.Error()
	} else {
		return quicsession, ""
	}

}

func IP_query(domain, iptype string) (string, string) {
	c := dns.Client{
		Timeout: timeout,
	}
	m := dns.Msg{}
	if iptype == "ipv4" {
		m.SetQuestion(domain+".", dns.TypeA)
	} else {
		m.SetQuestion(domain+".", dns.TypeAAAA)
	}

	m.RecursionDesired = true
	response, _, err := c.Exchange(&m, "8.8.8.8:53")
	if err != nil {
		return "Conn: " + err.(*net.OpError).Err.Error(), ""
	}

	if len(response.Answer) < 1 {
		return "Result: " + dns.RcodeToString[response.Rcode] + ";No DNS Answer", ""
	}

	answerList := ""
	for _, value := range response.Answer {
		if iptype == "ipv4" {
			record, isType := value.(*dns.A)
			if isType {
				answerList += record.A.String() + ";"
			}
		} else {
			record, isType := value.(*dns.AAAA)
			if isType {
				answerList += record.AAAA.String() + ";"
			}
		}
	}
	answerList = strings.TrimRight(answerList, ";")

	if answerList == "" {
		return "Result: " + dns.RcodeToString[response.Rcode] + ";No DNS Answer", ""
	}
	return "success", answerList
}

func DNS_answer_check(reply *dns.Msg) (bool, string, string) {
	if len(reply.Answer) < 1 {
		return false, "", dns.RcodeToString[reply.Rcode] + ";No Answer"
	}

	dnsAnswer := ""
	for _, value := range reply.Answer {
		record, isType := value.(*dns.A)
		if isType {
			dnsAnswer += record.A.String() + ";"
		}

	}
	dnsAnswer = strings.TrimRight(dnsAnswer, ";")
	//93.184.216.34
	if dnsAnswer == "" {
		return false, dnsAnswer, dns.RcodeToString[reply.Rcode] + ";No IP"
	} else if dnsAnswer != "8.210.162.129" {
		return false, dnsAnswer, dns.RcodeToString[reply.Rcode] + ";response err"
	} else {
		return true, dnsAnswer, ""
	}
}

// CheckSum 校验和计算
func CheckSum(data []byte) uint16 {
	var (
		sum    uint32
		length = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)
	return uint16(^sum)
}

func PingTest(ipStr, ipType string) (bool, string) {

	var pingOut []byte
	if ipType == "ipv4" {
		pingCmd := exec.Command("ping", "-c", "5", ipStr)
		pingOut, _ = pingCmd.Output()
	} else {
		pingCmd := exec.Command("ping6", "-c", "5", ipStr)
		pingOut, _ = pingCmd.Output()
	}

	for _, line := range strings.Split(string(pingOut), "\n") {
		if strings.Contains(line, "bytes") && strings.Contains(line, "time") {
			fields := strings.Fields(line)
			pingTime := strings.Split(fields[6], "=")[1]

			return true, pingTime
		}
	}
	return false, "Ping err"

}

func PingIpv4(ipStr string) (bool, string) {
	//构建发送的ICMP包
	icmp := ICMP{
		Type:     8,
		Code:     0,
		Checksum: 0, //默认校验和为0，后面计算再写入
		ID:       0,
		Seq:      0,
	}
	ip, err := net.ResolveIPAddr("ip4", ipStr)

	//新建buffer将包内数据写入，以计算校验和并将校验和并存入icmp结构体中
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, icmp)
	icmp.Checksum = CheckSum(buffer.Bytes())
	buffer.Reset()
	//与目的ip地址建立连接，第二个参数为空则默认为本地ip，第三个参数为目的ip
	con, err := net.DialIP("ip4:icmp", nil, ip)
	if err != nil {
		return false, "icmp conn err"
	}
	//主函数接术后关闭连接
	defer con.Close()
	//构建buffer将要发送的数据存入
	var sendBuffer bytes.Buffer
	binary.Write(&sendBuffer, binary.BigEndian, icmp)
	if _, err := con.Write(sendBuffer.Bytes()); err != nil {
		return false, "icmp write err"
	}
	//开始计算时间
	timeStart := time.Now()
	//设置读取超时时间为2s
	con.SetReadDeadline(time.Now().Add(time.Second * 5))
	//构建接受的比特数组
	rec := make([]byte, 1024)
	//读取连接返回的数据，将数据放入rec中
	_, err = con.Read(rec)
	if err != nil {
		return false, "icmp read err"
	}
	//设置结束时间，计算两次时间之差为ping的时间
	timeEnd := time.Now()
	durationTime := timeEnd.Sub(timeStart).Nanoseconds() / 1e6
	//显示结果
	//fmt.Printf("%d bytes from %s: seq=%d time=%dms\n", recCnt, ip.String(), icmp.Seq, durationTime)
	return true, strconv.FormatInt(durationTime, 10)

}

func QUICPing(ip, port, ipType string) (bool, string) {
	var udpconn net.Conn
	var udperr error
	if ipType == "ipv4" {
		fullAddr := ip + ":" + port
		udpconn, udperr = net.DialTimeout("udp4", fullAddr, 5*time.Second)
		if udperr != nil {
			temp := udperr.Error()
			if strings.Contains(temp, "timeout") {
				temp = "timeout"
			}
			return false, "udp conn err: " + temp
		}

	} else {
		fullAddr := "[" + ip + "]" + ":" + port
		udpconn, udperr = net.DialTimeout("udp6", fullAddr, 5*time.Second)
		if udperr != nil {
			temp := udperr.Error()
			if strings.Contains(temp, "timeout") {
				temp = "timeout"
			}
			return false, "udp conn err: " + temp
		}
	}

	defer udpconn.Close()

	send, dstID, srcID, buildErr := buildPacket()
	if buildErr != "" {
		return false, "build packet err: " + buildErr
	}
	udpconn.Write(send)

	//设置读取超时时间为2s
	udpconn.SetReadDeadline(time.Now().Add(time.Second * 5))

	buffer := make([]byte, 1024)
	n, err := udpconn.Read(buffer)
	if err != nil {
		temp := err.Error()
		if strings.Contains(temp, "timeout") {
			temp = "timeout"
		}
		return false, "udp read err: " + temp
	}

	quicVer, disErr := dissectVersionNegotiation(buffer[0:n], dstID, srcID)
	if disErr != "" {
		return false, "quic version err: " + disErr
	} else {
		return true, quicVer
	}

}

// formatHeader 格式化 HTTP header 为字符串
func FormatHeader(header http.Header) string {
	var headerStr string
	for key, values := range header {
		for _, value := range values {
			headerStr += fmt.Sprintf("%s: %s\n", key, value)
		}
	}
	return headerStr
}

// extractTitle 解析 HTML，提取 title 标签
func extractTitle(pageContent string) string {
	doc, err := html.Parse(strings.NewReader(pageContent))
	if err != nil {
		return ""
	}

	var title string
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
			title = n.FirstChild.Data
			return
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)

	return title
}

func GETHTTPSFP(HTTPTarget *Result) {

	queryDomain := HTTPTarget.ServerDomain
	queryIp := HTTPTarget.ServerIp

	HTTPTarget.PagePath = ""
	loopFlag := true
	redirectNum := 0
	var baseUrl string
	if queryIp != "" {
		if HTTPTarget.IpType == "ipv4" {
			baseUrl = "https://" + queryIp + "/" + HTTPTarget.PagePath
		} else {
			baseUrl = "https://" + "[" + queryIp + "]" + "/" + HTTPTarget.PagePath
		}

	} else {
		baseUrl = "https://" + queryDomain + "/" + HTTPTarget.PagePath
	}

	for loopFlag {
		var client *http.Client
		HTTPTarget.PageUrl = baseUrl
		HTTPTarget.PageRedirect = redirectNum

		if strings.Contains(baseUrl, "http://") {
			transport := &http.Transport{
				TLSClientConfig: nil,
			}

			client = &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					// 防止重定向，直接返回错误
					return http.ErrUseLastResponse
				},
				Timeout:   5 * time.Second,
				Transport: transport,
			}
		} else {

			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					//ServerName:         sni,
					MaxVersion: 0,
				},
			}
			client = &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					// 防止重定向，直接返回错误
					return http.ErrUseLastResponse
				},
				Timeout:   5 * time.Second,
				Transport: transport,
			}
		}

		res, err := client.Get(baseUrl)
		if err != nil {
			return
		}

		if redirectNum == 0 {
			_, certOut := CheckCertsChain(res.TLS.PeerCertificates, queryDomain, "true")
			if strings.Contains(certOut, "expired") {
				certOut = "expired"
			}
			HTTPTarget.PageCertErr = certOut

		}

		HTTPTarget.PageStatus = res.StatusCode
		//HTTPTarget.PageHeader = FormatHeader(res.Header)

		pageContent := ""
		buffer := make([]byte, 4096)
		for {
			n, err := res.Body.Read(buffer)
			if n > 0 {
				pageContent += string(buffer[:n])
			}
			if err != nil {
				break
			}
		}

		HTTPTarget.PageLen = len(pageContent)
		HTTPTarget.PageTitle = extractTitle(pageContent)
		if HTTPTarget.PageTitle == "" {
			if HTTPTarget.PageLen < 500 {
				HTTPTarget.PageTitle = pageContent
			}
		}

		if redirectNum < 5 && res.StatusCode >= 300 && res.StatusCode < 400 && res.Header.Get("Location") != "" {
			loopFlag = true
			redirectNum += 1

			if !strings.Contains(res.Header.Get("Location"), "http://") &&
				!strings.Contains(res.Header.Get("Location"), "https://") {
				baseUrl = baseUrl + res.Header.Get("Location")
			} else {
				baseUrl = res.Header.Get("Location")
			}

		} else {
			loopFlag = false

		}
	}
	return
}
