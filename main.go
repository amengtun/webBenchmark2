package main

import (
	"container/list"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apoorvam/goterminal"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	netstat "github.com/shirou/gopsutil/net"
)

const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

type speedPair struct {
	index uint64
	speed float64
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var SpeedQueue = list.New()
var SpeedIndex uint64 = 0
var SuccessCount uint64 = 0

type header struct {
	key, value string
}

type headersList []header

func (h *headersList) String() string {
	return fmt.Sprint(*h)
}

func (h *headersList) IsCumulative() bool {
	return true
}

func (h *headersList) Set(value string) error {
	res := strings.SplitN(value, ":", 2)
	if len(res) != 2 {
		return nil
	}
	*h = append(*h, header{
		res[0], strings.Trim(res[1], " "),
	})
	return nil
}

type ipArray []string

func (i *ipArray) String() string {
	return strings.Join(*i, ",")
}

func (i *ipArray) Set(value string) (err error) {
	*i = append(*i, strings.TrimSpace(value))
	return nil
}

func RandStringBytesMaskImpr(n int) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}

func generateRandomIPAddress() string {
	ip := fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
	return ip
}

func LeastSquares(x []float64, y []float64) (a float64, b float64) {
	xi := float64(0)
	x2 := float64(0)
	yi := float64(0)
	xy := float64(0)
	if len(x) != len(y) {
		a = 0
		b = 0
		return
	} else {
		length := float64(len(x))
		for i := 0; i < len(x); i++ {
			xi += x[i]
			x2 += x[i] * x[i]
			yi += y[i]
			xy += x[i] * y[i]
		}
		a = (yi*xi - xy*length) / (xi*xi - x2*length)
		b = (yi*x2 - xy*xi) / (x2*length - xi*xi)
	}
	return
}

func showStat() {
	initialNetCounter, _ := netstat.IOCounters(true)
	// iplist := ""
	// if customIP != nil && len(customIP) > 0 {
	// 	iplist = customIP.String()
	// } else {
	// 	u, _ := url.Parse(*downloadURL)
	// 	iplist = strings.Join(nslookup(u.Hostname(), "8.8.8.8"), ",")
	// }

	for {
		percent, _ := cpu.Percent(time.Second, false)
		memStat, _ := mem.VirtualMemory()
		netCounter, _ := netstat.IOCounters(true)
		loadStat, _ := load.Avg()

		fmt.Fprintf(TerminalWriter, "URL:%s\n", *downloadURL)
		// fmt.Fprintf(TerminalWriter, "IP:%s\n", iplist)
		fmt.Fprintf(TerminalWriter, "Success Count:%d\n", SuccessCount)
		fmt.Fprintf(TerminalWriter, "CPU:%.3f%% \n", percent)
		fmt.Fprintf(TerminalWriter, "Memory:%.3f%% \n", memStat.UsedPercent)
		fmt.Fprintf(TerminalWriter, "Load:%.3f %.3f %.3f\n", loadStat.Load1, loadStat.Load5, loadStat.Load15)
		for i := 0; i < len(netCounter); i++ {
			if netCounter[i].BytesRecv == 0 && netCounter[i].BytesSent == 0 {
				continue
			}
			RecvBytes := float64(netCounter[i].BytesRecv - initialNetCounter[i].BytesRecv)
			SendBytes := float64(netCounter[i].BytesSent - initialNetCounter[i].BytesSent)
			//if RecvBytes > 1000 {
			//	SpeedIndex++
			//	pair := speedPair{
			//		index: SpeedIndex,
			//		speed: RecvBytes,
			//	}
			//	SpeedQueue.PushBack(pair)
			//	if SpeedQueue.Len() > 60 {
			//		SpeedQueue.Remove(SpeedQueue.Front())
			//	}
			//	var x []float64
			//	var y []float64
			//	x = make([]float64, 60)
			//	y = make([]float64, 60)
			//	var point = 0
			//	for item := SpeedQueue.Front(); item != nil; item = item.Next() {
			//		spdPair := item.Value.(speedPair)
			//		x[point] = float64(spdPair.index)
			//		y[point] = spdPair.speed
			//		point++
			//	}
			//	_, b := LeastSquares(x, y)
			//	log.Printf("Speed Vertical:%.3f\n", b)
			//}
			fmt.Fprintf(TerminalWriter, "Nic:%v,Recv %s(%s/s),Send %s(%s/s)    \n", netCounter[i].Name,
				readableBytes(float64(netCounter[i].BytesRecv)),
				readableBytes(RecvBytes),
				readableBytes(float64(netCounter[i].BytesSent)),
				readableBytes(SendBytes))
		}
		initialNetCounter = netCounter
		TerminalWriter.Clear()
		TerminalWriter.Print()
		time.Sleep(1 * time.Millisecond)
	}
}

func readableBytes(bytes float64) (expression string) {
	if bytes == 0 {
		return "0B"
	}
	var i = math.Floor(math.Log(bytes) / math.Log(1024))
	var sizes = []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	return fmt.Sprintf("%.3f%s", bytes/math.Pow(1024, i), sizes[int(i)])
}

func clientFactory(Url string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if len(customIP) > 0 {
		dialer := &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			ip := customIP[rand.Intn(len(customIP))]
			if strings.HasPrefix(Url, "https") {
				addr = ip + ":443"
			} else if strings.HasPrefix(Url, "http") {
				addr = ip + ":80"
			} else {
				addr = ip + ":80"
			}
			// fmt.Println("DialContext addr:", addr)
			return dialer.DialContext(ctx, network, addr)
		}
	}

	if *socksProxy != "" {
		transport.Proxy = func(r *http.Request) (*url.URL, error) {
			return url.Parse("socks5://" + *socksProxy)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Second * 10,
	}
}

func goFun(Url string, postContent string, Referer string, XforwardFor bool, customIP ipArray) {
	// sstat := *stat
	randQuery := *randq
	client := clientFactory(Url)

	defer func() {
		if r := recover(); r != nil {
			go goFun(Url, postContent, Referer, XforwardFor, customIP)
		}
	}()

	for {
		if !*reuseClient {
			client = clientFactory(Url)
		}

		var request *http.Request
		var err1 error

		Url2 := Url
		if randQuery {
			Url2 += "?" + RandStringBytesMaskImpr(10) + "=" + RandStringBytesMaskImpr(10)
		}
		if len(postContent) > 0 {
			request, err1 = http.NewRequest("POST", Url2, strings.NewReader(postContent))
		} else {
			request, err1 = http.NewRequest("GET", Url2, nil)
		}
		if err1 != nil {
			continue
		}
		if len(Referer) == 0 {
			Referer = Url
		}
		// request.Header.Add("Cookie", RandStringBytesMaskImpr(12))
		// request.Header.Add("User-Agent", browser.Random())
		request.Header.Add("Referer", Referer)
		if XforwardFor {
			randomip := generateRandomIPAddress()
			request.Header.Add("X-Forwarded-For", randomip)
			request.Header.Add("X-Real-IP", randomip)
		}

		if len(headers) > 0 {
			for _, head := range headers {
				headKey := head.key
				headValue := head.value
				if strings.HasPrefix(head.key, "Random") {
					count, convErr := strconv.Atoi(strings.ReplaceAll(head.value, "Random", ""))
					if convErr == nil {
						headKey = RandStringBytesMaskImpr(count)
					}
				}
				if strings.HasPrefix(head.value, "Random") {
					count, convErr := strconv.Atoi(strings.ReplaceAll(head.value, "Random", ""))
					if convErr == nil {
						headValue = RandStringBytesMaskImpr(count)
					}
				}
				request.Header.Del(headKey)
				request.Header.Set(headKey, headValue)
			}
		}

		resp, err2 := client.Do(request)
		if err2 != nil {
			continue
		}

		respStr := fmt.Sprintln(resp)
		if resp.StatusCode != 200 {
			log.Println(request)
			log.Println("[MAYBE FUCKED]", respStr)
		} else if strings.Contains(respStr, "HIT") {
			log.Println(request)
			log.Println("[MAYBE CACHE HIT]", respStr)
		} else {
			SuccessCount++
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if !*reuseClient {
			client.CloseIdleConnections()
		}
	}
}

var h = flag.Bool("h", false, "this help")
var count = flag.Int("c", 16, "concurrent thread for download,default 16")
var reuseClient = flag.Bool("reuse", false, "reuse the client")
var downloadURL = flag.String("s", "", "target url")
var stat = flag.Bool("stat", false, "show stat")
var randq = flag.Bool("rand", true, "rand query")
var postContent = flag.String("p", "", "post content")
var referer = flag.String("r", "", "referer url")
var xforwardfor = flag.Bool("f", true, "randomized X-Forwarded-For and X-Real-IP address")
var socksProxy = flag.String("proxy", "", "socks5 proxy")
var TerminalWriter = goterminal.New(os.Stderr)
var customIP ipArray
var headers headersList

func main() {
	rand.Seed(time.Now().Unix())
	flag.Var(&customIP, "i", "custom ip address for that domain, multiple addresses automatically will be assigned randomly")
	flag.Var(&headers, "H", "custom header")
	flag.Parse()
	if *h || *downloadURL == "" {
		flag.Usage()
		return
	}
	routines := *count

	if len(customIP) > 0 && routines < len(customIP) {
		routines = len(customIP)
	}

	if *stat {
		go showStat()
	}

	var waitgroup sync.WaitGroup
	if routines <= 0 {
		routines = 16
	}
	for i := 0; i < routines; i++ {
		waitgroup.Add(1)
		go goFun(*downloadURL, *postContent, *referer, *xforwardfor, customIP)
	}
	waitgroup.Wait()
	TerminalWriter.Reset()
}
