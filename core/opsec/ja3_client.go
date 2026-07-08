package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Request defines the JSON input format
type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Browser string            `json:"browser"` // e.g., "chrome", "firefox"
}

// Response defines the JSON output format
type Response struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Error      string            `json:"error,omitempty"`
}

// getClientHelloID maps string to utls ClientHelloID
func getClientHelloID(browser string) tls.ClientHelloID {
	switch browser {
	case "firefox":
		return tls.HelloFirefox_Auto
	case "ios":
		return tls.HelloIOS_Auto
	case "edge":
		return tls.HelloEdge_Auto
	case "safari":
		return tls.HelloSafari_Auto
	case "random":
		return tls.HelloRandomized
	default:
		return tls.HelloChrome_Auto // Default to Chrome
	}
}

func main() {
	inputFile := flag.String("in", "", "Path to JSON input file")
	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Usage: ja3_client -in <request.json>")
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(*inputFile)
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		return
	}

	var reqData Request
	if err := json.Unmarshal(data, &reqData); err != nil {
		outputError(fmt.Sprintf("Failed to parse JSON: %v", err))
		return
	}

	// Setup custom dialer with uTLS
	dialTLS := func(network, addr string) (*tls.UConn, error) {
		conn, err := tls.Dial(network, addr, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return nil, err
		}
		
		clientHello := getClientHelloID(reqData.Browser)
		uConn := tls.UClient(conn, &tls.Config{InsecureSkipVerify: true}, clientHello)
		
		if err := uConn.Handshake(); err != nil {
			return nil, err
		}
		return uConn, nil
	}

	// Create custom transport
	transport := &http.Transport{
		DialTLS: func(network, addr string) (netConn net.Conn, err error) {
			return dialTLS(network, addr)
		},
		DisableKeepAlives: false,
		MaxIdleConns:      10,
		IdleConnTimeout:   30 * time.Second,
	}
	
	// Force HTTP/2 with strict browser-like settings
	// uTLS doesn't automatically handle all HTTP/2 ALPN frame settings.
	// We configure x/net/http2 transport to mimic strict browser SETTINGS frames.
	t2, err := http2.ConfigureTransports(transport)
	if err != nil {
		outputError(fmt.Sprintf("Failed to configure HTTP2: %v", err))
		return
	}
	
	// Align SETTINGS frames closer to Chrome (MaxConcurrentStreams, InitialWindowSize)
	t2.StrictMaxConcurrentStreams = true
	t2.ReadIdleTimeout = 30 * time.Second
	t2.PingTimeout = 15 * time.Second

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	var reqBody *bytes.Reader
	if reqData.Body != "" {
		reqBody = bytes.NewReader([]byte(reqData.Body))
	} else {
		reqBody = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequest(reqData.Method, reqData.URL, reqBody)
	if err != nil {
		outputError(fmt.Sprintf("Failed to create request: %v", err))
		return
	}

	for k, v := range reqData.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		outputError(fmt.Sprintf("Request failed: %v", err))
		return
	}
	defer resp.Body.Close()

	respBodyBytes, _ := ioutil.ReadAll(resp.Body)
	
	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}

	finalResp := Response{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       string(respBodyBytes),
	}

	outData, _ := json.Marshal(finalResp)
	fmt.Println(string(outData))
}

func outputError(msg string) {
	resp := Response{Error: msg}
	out, _ := json.Marshal(resp)
	fmt.Println(string(out))
}
