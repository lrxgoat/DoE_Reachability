package main

import (
	"Block_Check/check"
	"Block_Check/metrics"
	"bufio"
	"flag"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var GtIPMap map[string]string
var GtASMap map[string]string

func run(jobs <-chan string, ScanFile, certFile, queryType, queryPort, sni, ipType, httpVer, httpMethod, vpn, vpnconfig,
	checkTime string, retryNum int, gt string, wg *sync.WaitGroup, limiter *rate.Limiter, ctx context.Context) {
	defer wg.Done()
	scanF, err_ := os.Create(ScanFile)
	if err_ != nil {
		fmt.Println(err_.Error())
	}

	certF, err_ := os.Create(certFile)
	if err_ != nil {
		fmt.Println(err_.Error())
	}

	for line := range jobs {

		limiter.Wait(ctx)
		var scanResult string
		var certResult string
		Target := new(metrics.Result)
		Target.ScanPort = queryPort
		Target.CheckTime = checkTime
		Target.IpType = ipType
		Target.VPNServer = vpn
		Target.VPNConfig = vpnconfig
		Target.ScanType = queryType
		Target.ServerDomain = strings.Split(line, ",")[0]

		var answerList string
		var dnsResult string

		dnsScanFlag := false
		dnsScanNum := 1
		for dnsScanFlag == false {
			//fmt.Println(line, dnsScanNum)
			if sni == "true" {
				dnsResult, answerList = metrics.IP_query(Target.ServerDomain, ipType)
			} else {
				answerList = line
				dnsResult = "success"
			}

			if dnsResult == "success" {
				Target.DNSQueryResult = answerList
				dnsScanFlag = true
			}

			if dnsScanNum == retryNum && dnsResult != "success" {
				dnsScanFlag = true

				Target.DNSQueryResult = answerList
				scanResult = metrics.WriteResult(Target, "Pre-resolve", dnsResult) + "\n"
				scanF.WriteString(scanResult)
			} else {
				dnsScanNum += 1
			}

			time.Sleep(2 * time.Second)
		}

		if dnsResult != "success" {
			continue
		}

		for _, value := range strings.Split(answerList, ";") {
			Target.ServerIp = value

			if metrics.IsIPBogon(value, ipType) {
				scanResult = metrics.WriteResult(Target, "Pre-resolve", "Result: Bogon IP") + "\n"
				scanF.WriteString(scanResult)

			} else {

				if gt == "true" {
					if strings.Contains(GtIPMap[Target.ServerDomain], Target.ServerIp) {
						Target.SuspectFlag = true
						Target.SuspectResult = "IP true"
					}
				}

				metrics.GETHTTPSFP(Target)

				successFlag := false
				scantNum := 1
				var tempFlag bool
				for successFlag == false {

					switch queryType {
					case "dot":
						tempFlag, scanResult, certResult = check.DoT_Verify(Target, sni, ipType)

					case "doh":
						Target.HTTPMethod = httpMethod
						Target.HTTPVersion = httpVer

						if len(strings.Split(line, ",")) != 2 {
							Target.HTTPPath = "dns-query"
						} else {
							Target.HTTPPath = strings.Split(line, ",")[1]
						}

						tempFlag, scanResult, certResult = check.DoH_Verify(Target, sni, ipType, httpVer, httpMethod)

					case "doq":
						tempFlag, scanResult, certResult = check.DoQ_Verify(Target, sni, ipType)

					case "doh3":
						Target.HTTPMethod = httpMethod
						Target.HTTPVersion = "http/3"

						if len(strings.Split(line, ",")) != 2 {
							Target.HTTPPath = "dns-query"
						} else {
							Target.HTTPPath = strings.Split(line, ",")[1]
						}

						tempFlag, scanResult, certResult = check.DoH3_Verify(Target, sni, ipType, httpMethod)

					default:
						fmt.Println(line + "parameter err")
						os.Exit(3)

					}

					if tempFlag {
						successFlag = true
						scanF.WriteString(scanResult)
						if certResult != "" {
							certF.WriteString(certResult)
						}

					}

					if scantNum == retryNum && successFlag == false {
						successFlag = true
						scanF.WriteString(scanResult)
						if certResult != "" {
							certF.WriteString(certResult)
						}
					} else {
						scantNum += 1
					}

					time.Sleep(2 * time.Second)
				}
			}
		}
	}
	scanF.Close()
}

func main() {
	var numThreads = flag.Int("n", 100, "Number of threads")
	var inputFile = flag.String("i", "./input.txt", "Input File")
	var resultDir = flag.String("o", "./result/", "Output File")
	var queryType = flag.String("t", "doq", "DoT or DoH or DoQ or DoH3")
	var queryPort = flag.String("p", "853", "Query Port")

	var sni = flag.String("s", "true", "SNI")
	var ipType = flag.String("a", "ipv4", "IP Type")
	var httpVer = flag.String("h", "h1", "HTTP Version")
	var httpMethod = flag.String("m", "GET", "HTTP Method")

	var vpn = flag.String("v", "VPN", "VPN server")
	var vpnconfig = flag.String("c", "VPN", "VPN config file")
	var retryNum = flag.Int("r", 3, "Scan retry num")
	var checkTime = flag.String("f", "2023", "check time")

	var gtfile string
	var gt string
	flag.StringVar(&gtfile, "gtfile", "", "gtfile")

	flag.StringVar(&gt, "gt", "true", "gt")

	startTime := time.Now()
	fmt.Println("start scan at:", startTime)

	flag.Parse()

	fmt.Println(gt)
	fmt.Println(gtfile)
	QPS := *numThreads // 令牌桶算法，往桶里面放令牌的速度，可以理解为每秒的发包数量，根据带宽大小设定
	jobs := make(chan string)
	var wg sync.WaitGroup
	limiter := rate.NewLimiter(rate.Limit(QPS), 1)
	ctx := context.Background()

	GtIPMap = metrics.ReadJson(gtfile, "ip")

	for w := 0; w < *numThreads; w++ {
		go func(wgScoped *sync.WaitGroup, limiterScoped *rate.Limiter, i int, ctxScoped context.Context) {
			wgScoped.Add(1)

			scanFile := *resultDir + "scan-" + strconv.Itoa(i) + ".txt"
			certFile := *resultDir + "cert-" + strconv.Itoa(i) + ".txt"
			run(jobs, scanFile, certFile, *queryType, *queryPort, *sni, *ipType, *httpVer, *httpMethod, *vpn, *vpnconfig, *checkTime, *retryNum, gt, wgScoped, limiterScoped, ctxScoped)
		}(&wg, limiter, w, ctx)
	}

	inputf, err := os.Open(*inputFile)
	if err != nil {
		err.Error()
	}
	scanner := bufio.NewScanner(inputf)

	for scanner.Scan() {
		jobs <- scanner.Text()
	}
	close(jobs)
	wg.Wait()

	inputf.Close()

	mergeErr := metrics.FileMerge(*resultDir+"scan-*", *resultDir+"result_scan.txt")
	if mergeErr != "success" {
		fmt.Println("scan file merge err")
	}

	mergeErr = metrics.FileMerge(*resultDir+"cert-*", *resultDir+"result_cert.txt")
	if mergeErr != "success" {
		fmt.Println("scan file merge err")
	}

	endTime := time.Now()
	fmt.Println("end scan at:", endTime)
	fmt.Println("duration:", time.Since(startTime).String())

}
