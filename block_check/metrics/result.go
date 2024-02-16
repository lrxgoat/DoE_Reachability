package metrics

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"time"
)

var TLSVerDict = map[uint16]string{
	tls.VersionTLS10: "tls1_0",
	tls.VersionTLS11: "tls1_1",
	tls.VersionTLS12: "tls1_2",
	tls.VersionTLS13: "tls1_3",
}

type Result struct {
	ServerIp     string `json:"server_ip"`
	ServerDomain string `json:"server_domain"`
	ScanPort     string `json:"scan_port"`
	QueryDomain  string `json:"query_domain"`

	CheckTime string `json:"check_time"`
	IpType    string `json:"ip_type"`
	ScanType  string `json:"scan_type"`

	//Block       bool   `json:"block"`
	BlockType string `json:"block_type"`
	BlockErr  string `json:"block_err"`

	DNSQueryResult string `json:"dns_query_result"`
	ICMPRtt        string `json:"icmp_rtt"`
	QUICVNResult   string `json:"quic_vn_result"`
	DoEQueryResult string `json:"doe_query_result"`

	CertValid bool `json:"cert_valid"`
	//CertChainHash string   `json:"cert_chain_hash"`
	CertCA     string   `json:"cert_ca"`
	CertBefore string   `json:"cert_before"`
	CerAfter   string   `json:"cer_after"`
	CertLife   float64  `json:"cert_life"`
	CertCN     string   `json:"cert_cn"`
	CertSAN    []string `json:"cert_san"`
	CertErr    string   `json:"cert_err"`
	TLSVersion string   `json:"tls_version"`

	HTTPStatus  int    `json:"http_status"`
	HTTPPath    string `json:"http_path"`
	HTTPVersion string `json:"http_version"`
	HTTPMethod  string `json:"http_method"`
	//HTTPHeader  string `json:"http_header"`

	VPNServer string `json:"vpn_server"`
	VPNConfig string `json:"vpn_config"`

	PageUrl    string `json:"page_url"`
	PageStatus int    `json:"page_status"`
	PagePath   string `json:"page_path"`
	//PageCert    string `json:"page_cert"`
	PageCertErr string `json:"page_cert_err"`
	//PageHeader   string `json:"page_header"`
	PageTitle    string `json:"page_title"`
	PageRaw      string `json:"page_raw"`
	PageLen      int    `json:"page_len"`
	PageRedirect int    `json:"page_redirect"`

	SuspectFlag   bool   `json:"suspect_flag"`
	SuspectResult string `json:"suspect_result"`
	//SuspectCert   string `json:"suspect_cert"`
}

type CertResult struct {
	ServerIp     string `json:"server_ip"`
	ServerDomain string `json:"server_domain"`
	CheckTime    string `json:"check_time"`
	VPNServer    string `json:"vpn_server"`
	IpType       string `json:"ip_type"`
	ScanType     string `json:"scan_type"`
	//CertChainHash string `json:"cert_chain_hash"`
	CertChainRaw string `json:"cert_chain_raw"`
}

func FileMerge(originalFile string, finalFile string) string {
	in := bytes.NewBuffer(nil)
	cmd := exec.Command("sh")
	cmd.Stdin = in
	in.WriteString("for i in " + originalFile + ";do cat $i >> " + finalFile + ";done\n")
	in.WriteString("sleep 5s\n")
	in.WriteString("rm " + originalFile + "\n")
	in.WriteString("exit\n")
	if err := cmd.Run(); err != nil {
		return "err"
	} else {
		return "success"
	}
}

type ASResult struct {
	DoHServer   string `json:"doh_server"`
	QueryDomain string `json:"query_domain"`
	AResult     string `json:"a_result"`
	AAAAResult  string `json:"aaaa_result"`
	ASInfo      string `json:"as_info"`
}

//type ASOutResult struct {
//	ServerIp     string `json:"server_ip"`
//	ServerDomain string `json:"server_domain"`
//
//	CheckTime string `json:"check_time"`
//	IpType    string `json:"ip_type"`
//
//	VPNServer string `json:"vpn_server"`
//	VPNConfig string `json:"vpn_config"`
//}

type IPInfo struct {
	Status       string  `json:"status"`
	Country      string  `json:"country"`
	CountryCode  string  `json:"countryCode"`
	Region       string  `json:"region"`
	RegionName   string  `json:"regionName"`
	City         string  `json:"city"`
	Zip          string  `json:"zip"`
	Lat          float64 `json:"lat"`
	Lon          float64 `json:"lon"`
	Timezone     string  `json:"timezone"`
	ISP          string  `json:"isp"`
	Organization string  `json:"org"`
	AS           string  `json:"AS"`
	Query        string  `json:"query"`
}

//type ASResult struct {
//	ServerIp     string `json:"server_ip"`
//	ServerDomain string `json:"server_domain"`
//	ASResult     string `json:"as_result"`
//}

type QuicPingResult struct {
	ServerIp     string `json:"server_ip"`
	ServerDomain string `json:"server_domain"`
	IpType       string `json:"ip_type"`
	ScanType     string `json:"scan_type"`
	QuicVer      string `json:"quic_ver"`
}

type SuspectIpResult struct {
	ServerIp     string `json:"server_ip"`
	ServerDomain string `json:"server_domain"`
	ErrType      string `json:"err_type"`
	ErrResult    string `json:"err_result"`
}

type HTTPFPResult struct {
	ServerIp     string `json:"server_ip"`
	ServerDomain string `json:"server_domain"`
	IpType       string `json:"ip_type"`

	PagePath     string `json:"page_path"`
	PageUrl      string `json:"page_url"`
	PageStatus   int    `json:"page_status"`
	PageHeader   string `json:"page_header"`
	PageTitle    string `json:"page_title"`
	PageRaw      string `json:"page_raw"`
	PageLen      int    `json:"page_len"`
	PageRedirect int    `json:"page_redirect"`
}

func WriteResult(Target *Result, ErrType string, connErr string) string {
	//Target.Block = Block
	Target.BlockType = ErrType
	Target.BlockErr = connErr
	outresult, _ := json.Marshal(Target)
	return string(outresult)
}

func CertSha256(certStr string) string {
	// 创建SHA-256哈希对象
	hash := sha256.New()

	// 将字符串转换为字节数组，并写入哈希对象
	hash.Write([]byte(certStr))

	// 计算哈希值并获取结果
	hashValue := hash.Sum(nil)

	// 将哈希值转换为十六进制字符串
	hashString := hex.EncodeToString(hashValue)

	return hashString
}

func GetAS(testIP string) string {
	getFlag := false
	checkNum := 0

	rand.Seed(time.Now().UnixNano())
	// 生成四位随机数
	randNum := rand.Intn(20) + 100

	for getFlag == false {

		queryUrl := "http://ip-api.com/json/" + testIP

		transport := &http.Transport{
			TLSClientConfig: nil,
		}

		client := &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		}

		resp, err := client.Get(queryUrl)
		if err != nil {
			fmt.Println(checkNum, err)
			checkNum += 1

			if checkNum == 50 {
				getFlag = true
				return "failed"
			}
			time.Sleep(time.Duration(randNum) * time.Second)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			var ipInfo IPInfo
			err = json.NewDecoder(resp.Body).Decode(&ipInfo)
			if err != nil {
				getFlag = true
				return "failed"
			}
			return ipInfo.AS
		} else if resp.StatusCode == 429 {
			time.Sleep(time.Duration(randNum) * time.Second)
			checkNum += 1
		} else {
			time.Sleep(time.Duration(randNum) * time.Second)
			checkNum += 1
		}

		if checkNum == 50 {
			getFlag = true
			return "failed"
		}

	}
	return "failed"

}

func ReadJson(inputFile, structType string) map[string]string {
	var outtMap = map[string]string{
		"dnsavailable.xyz;8.210.162.129": "as",
	}

	tempf, temperr := os.Open(inputFile)
	if temperr != nil {
		temperr.Error()
	}
	tempscanner := bufio.NewScanner(tempf)
	for tempscanner.Scan() {
		switch structType {
		case "ip":
			var temp ASResult
			_ = json.Unmarshal([]byte(tempscanner.Text()), &temp)
			outtMap[temp.QueryDomain] = temp.AResult + temp.AAAAResult

		case "as":
			var temp ASResult
			_ = json.Unmarshal([]byte(tempscanner.Text()), &temp)
			outtMap[temp.QueryDomain] = temp.ASInfo

		//case "cert":
		//	var temp CertResult
		//	_ = json.Unmarshal([]byte(tempscanner.Text()), &temp)
		//	outtMap[temp.ServerDomain] = temp.CertChainHash

		case "pagetitle":
			var temp HTTPFPResult
			_ = json.Unmarshal([]byte(tempscanner.Text()), &temp)
			outtMap[temp.ServerDomain] = temp.PageTitle

		case "pageraw":
			var temp HTTPFPResult
			_ = json.Unmarshal([]byte(tempscanner.Text()), &temp)
			outtMap[temp.ServerDomain] = temp.PageRaw

		case "quicping":
			var temp QuicPingResult
			_ = json.Unmarshal([]byte(tempscanner.Text()), &temp)
			outtMap[temp.ServerDomain] = temp.QuicVer

		}

	}
	tempf.Close()
	return outtMap
}
