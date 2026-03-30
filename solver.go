package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	mrand "math/rand"
	"mime/multipart"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

type CryptoConfig struct {
	Key           []byte
	KeyHex        string
	Identifier    string
	TypeNames     map[string]string
	SignalVersion string
}

type AWSWAFSession struct {
	TargetURL          string
	Domain             string
	Proxy              string
	Proxies            []string
	Jar                *CookieJar
	UserAgent          string
	ChromeVersion      string
	ScreenW            int
	ScreenH            int
	ChallengeScriptURL string
	ChallengeBaseURL   string
	WAFToken           string
	SessionStorage     string
	Crypto             *CryptoConfig
}

type TelemetryResponse struct {
	Token    string          `json:"token,omitempty"`
	Inputs   json.RawMessage `json:"inputs,omitempty"`
	Response *InnerResponse  `json:"response,omitempty"`
}

type InnerResponse struct {
	Token              string          `json:"token,omitempty"`
	Inputs             json.RawMessage `json:"inputs,omitempty"`
	AWSWAFSessionStore string          `json:"awswaf_session_storage,omitempty"`
	NextInterval       *int            `json:"next_interval,omitempty"`
}

type ChallengeInputs struct {
	Challenge     ChallengeData `json:"challenge"`
	ChallengeType string        `json:"challenge_type"`
	Difficulty    int           `json:"difficulty"`
	Memory        int           `json:"memory"`
}

type ChallengeData struct {
	Input  string `json:"input"`
	Hmac   string `json:"hmac"`
	Region string `json:"region"`
}

func NewAWSWAFSession(targetURL string, proxy string, proxies []string) *AWSWAFSession {
	screens := [][2]int{
		{1920, 1080}, {2560, 1440}, {1366, 768}, {1536, 864},
		{1440, 900}, {1680, 1050}, {1280, 720}, {1600, 900},
	}
	scr := screens[mrand.Intn(len(screens))]
	chromeMajor := []string{"131", "132", "133"}[mrand.Intn(3)]
	chromeVer := chromeMajor + ".0.0.0"

	return &AWSWAFSession{
		TargetURL:     targetURL,
		Domain:        extractHost(targetURL),
		Proxy:         proxy,
		Proxies:       proxies,
		Jar:           NewCookieJar(),
		UserAgent:     fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", chromeVer),
		ChromeVersion: chromeMajor,
		ScreenW:       scr[0],
		ScreenH:       scr[1],
	}
}

func (s *AWSWAFSession) browserHeaders() map[string]string {
	cookies := s.Jar.Get(s.Domain)
	h := map[string]string{
		"Host":                      s.Domain,
		"sec-ch-ua":                 fmt.Sprintf(`"Chromium";v="%s", "Google Chrome";v="%s", "Not-A.Brand";v="8"`, s.ChromeVersion, s.ChromeVersion),
		"sec-ch-ua-mobile":          "?0",
		"sec-ch-ua-platform":        `"Windows"`,
		"upgrade-insecure-requests": "1",
		"user-agent":                s.UserAgent,
		"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		"sec-fetch-site":            "none",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-user":            "?1",
		"sec-fetch-dest":            "document",
		"accept-encoding":           "gzip, deflate, br",
		"accept-language":           "en-US,en;q=0.9",
	}
	if cookies != "" {
		h["Cookie"] = cookies
	}
	return h
}

func (s *AWSWAFSession) challengeHeaders() map[string]string {
	challengeHost := extractHost(s.ChallengeBaseURL)
	return map[string]string{
		"Host":               challengeHost,
		"user-agent":         s.UserAgent,
		"accept":             "*/*",
		"accept-encoding":    "gzip, deflate, br",
		"accept-language":    "en-US,en;q=0.9",
		"content-type":       "text/plain;charset=UTF-8",
		"origin":             fmt.Sprintf("https://%s", s.Domain),
		"referer":            fmt.Sprintf("https://%s/", s.Domain),
		"sec-ch-ua":          fmt.Sprintf(`"Chromium";v="%s", "Google Chrome";v="%s", "Not-A.Brand";v="8"`, s.ChromeVersion, s.ChromeVersion),
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": `"Windows"`,
		"sec-fetch-dest":     "empty",
		"sec-fetch-mode":     "cors",
		"sec-fetch-site":     "cross-site",
	}
}

func (s *AWSWAFSession) Solve() bool {
	logPhase("fetching target page")
	logInfo("url     :: %s", s.TargetURL)
	pageHTML, err := s.fetchPage()
	if err != nil {
		logFail("fetch page :: %v", err)
		return false
	}

	scriptURL, found := s.extractChallengeScriptURL(pageHTML)
	if !found {
		logFail("no AWS WAF challenge script found in page")
		if !strings.Contains(pageHTML, "awswaf") {
			logWarn("page may not have AWS WAF protection")
		}
		return false
	}
	s.ChallengeScriptURL = scriptURL
	s.ChallengeBaseURL = extractChallengeBase(scriptURL)
	logSuccess("script  :: %s", scriptURL)
	logSuccess("base    :: %s", s.ChallengeBaseURL)

	cookieDomains := s.extractCookieDomains(pageHTML)
	logInfo("domains :: %v", cookieDomains)

	logPhase("fetching challenge.js")
	challengeScript, err := s.fetchChallengeScript()
	if err != nil {
		logFail("fetch challenge.js :: %v", err)
		return false
	}
	logSuccess("size    :: %d bytes", len(challengeScript))

	logPhase("extracting crypto config")
	cryptoConfig, err := s.extractCryptoConfig(challengeScript)
	if err != nil {
		logFail("crypto extraction :: %v", err)
		return false
	}
	s.Crypto = cryptoConfig

	challengeInputs := s.extractChallengeInputs(challengeScript)
	if challengeInputs == nil {
		logFail("could not extract challenge inputs from script")
		return false
	}
	logSuccess("challenge :: type=%s diff=%d mem=%d",
		truncate(challengeInputs.ChallengeType, 20), challengeInputs.Difficulty, challengeInputs.Memory)

	logPhase("solving challenge")
	resp, err := s.solveAndPost(challengeInputs)
	if err != nil {
		logFail("solve+post :: %v", err)
		return false
	}

	return s.processResponse(resp, challengeInputs)
}

func (s *AWSWAFSession) challengeTypeName(hash string) string {
	if s.Crypto != nil && s.Crypto.TypeNames != nil {
		if name, ok := s.Crypto.TypeNames[hash]; ok {
			return name
		}
	}

	switch {
	case strings.HasPrefix(hash, "ha9faaffd"):
		return "mp_verify"
	case strings.HasPrefix(hash, "h72f957df"):
		return "verify"
	case strings.HasPrefix(hash, "h7b0c470f"):
		return "verify"
	default:
		return "mp_verify"
	}
}

func (s *AWSWAFSession) solveAndPost(ci *ChallengeInputs) (*TelemetryResponse, error) {
	startTime := time.Now()

	signals := s.buildSignals()
	signalsArray, checksum, err := s.encodeSignals(signals)
	if err != nil {
		return nil, fmt.Errorf("encode signals: %w", err)
	}
	signalTime := time.Since(startTime)

	solveStart := time.Now()
	solution, err := s.solveChallenge(ci, checksum)
	if err != nil {
		return nil, fmt.Errorf("solve challenge: %w", err)
	}
	solveTime := time.Since(solveStart)
	logSuccess("solved  :: %v  %s", solveTime, truncate(solution, 80))

	existingToken := s.Jar.GetValue(s.Domain, "aws-waf-token")

	cookieStart := time.Now()
	_ = existingToken
	cookieTime := time.Since(cookieStart)
	totalTime := time.Since(startTime)

	metrics := []map[string]interface{}{}
	if existingToken != "" {
		metrics = append(metrics, map[string]interface{}{"name": "ExistingTokenFound", "value": 1, "unit": "Count"})
	} else {
		metrics = append(metrics, map[string]interface{}{"name": "ExistingTokenFound", "value": 0, "unit": "Count"})
	}
	metrics = append(metrics,
		map[string]interface{}{"name": "SignalAcquisitionTime", "value": int(signalTime.Milliseconds()), "unit": "Milliseconds"},
		map[string]interface{}{"name": "ChallengeExecutionTime", "value": int(solveTime.Milliseconds()), "unit": "Milliseconds"},
		map[string]interface{}{"name": "CookieFetchLatency", "value": int(cookieTime.Milliseconds()), "unit": "Milliseconds"},
		map[string]interface{}{"name": "TotalTime", "value": int(totalTime.Milliseconds()), "unit": "Milliseconds"},
	)

	payload := map[string]interface{}{
		"challenge": map[string]interface{}{
			"input":  ci.Challenge.Input,
			"hmac":   ci.Challenge.Hmac,
			"region": ci.Challenge.Region,
		},
		"solution":   solution,
		"signals":    signalsArray,
		"checksum":   checksum,
		"client":     "Browser",
		"domain":     s.Domain,
		"metrics":    metrics,
		"goku_props": nil,
	}
	if existingToken != "" {
		payload["existing_token"] = existingToken
	}

	typeName := s.challengeTypeName(ci.ChallengeType)
	submitURL := s.ChallengeBaseURL + "/" + typeName
	headers := s.challengeHeaders()

	var bodyBytes []byte

	if typeName == "verify" {
		bodyBytes, _ = json.Marshal(payload)
	} else {
		solutionData := solution
		payload["solution"] = nil
		metadataJSON, _ := json.Marshal(payload)

		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		writer.WriteField("solution_data", solutionData)
		writer.WriteField("solution_metadata", string(metadataJSON))
		writer.Close()

		bodyBytes = buf.Bytes()
		headers["content-type"] = writer.FormDataContentType()
	}

	logPhase("posting solution")
	logInfo("post    :: %s (%d bytes, type=%s)", submitURL, len(bodyBytes), typeName)

	resp, err := DoRequest(submitURL, RequestOpts{
		Method:  "POST",
		Headers: headers,
		Body:    bodyBytes,
		Proxy:   s.Proxy,
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("challenge POST failed: %w", err)
	}

	logInfo("status  :: %d  body=%s", resp.Status, truncate(string(resp.Body), 200))

	if resp.Status != 200 {
		return nil, fmt.Errorf("challenge POST returned status %d: %s", resp.Status, truncate(string(resp.Body), 300))
	}

	var telResp TelemetryResponse
	if err := json.Unmarshal(resp.Body, &telResp); err != nil {
		return nil, fmt.Errorf("response parse failed: %w (body: %s)", err, truncate(string(resp.Body), 200))
	}

	return &telResp, nil
}

func (s *AWSWAFSession) processResponse(resp *TelemetryResponse, inputs *ChallengeInputs) bool {
	if resp.Token != "" {
		logSuccess("token received directly")
		s.setWAFToken(resp.Token)
		return true
	}

	if resp.Response != nil {
		if resp.Response.Token != "" {
			logSuccess("token received from response")
			s.setWAFToken(resp.Response.Token)
			return true
		}
		if resp.Response.AWSWAFSessionStore != "" {
			s.SessionStorage = resp.Response.AWSWAFSessionStore
		}
		if resp.Response.Inputs != nil {
			logWarn("server sent new challenge inputs, retrying")
			var newCI ChallengeInputs
			if err := json.Unmarshal(resp.Response.Inputs, &newCI); err != nil {
				logFail("parse new inputs :: %v", err)
				return false
			}
			if newCI.Memory == 0 && inputs != nil {
				newCI.Memory = inputs.Memory
			}
			retryResp, err := s.solveAndPost(&newCI)
			if err != nil {
				logFail("retry :: %v", err)
				return false
			}
			return s.processResponse(retryResp, inputs)
		}
	}

	if resp.Inputs != nil {
		logWarn("got challenge inputs in response, solving")
		var ci ChallengeInputs
		if err := json.Unmarshal(resp.Inputs, &ci); err != nil {
			logFail("parse inputs :: %v", err)
			return false
		}
		if ci.Memory == 0 && inputs != nil {
			ci.Memory = inputs.Memory
		}
		retryResp, err := s.solveAndPost(&ci)
		if err != nil {
			logFail("retry :: %v", err)
			return false
		}
		return s.processResponse(retryResp, inputs)
	}

	logFail("no token and no challenge in response")
	return false
}

func (s *AWSWAFSession) fetchPage() (string, error) {
	resp, err := DoRequestFollowRedirects(s.TargetURL, RequestOpts{
		Method:  "GET",
		Headers: s.browserHeaders(),
		Proxy:   s.Proxy,
		Timeout: 15 * time.Second,
	}, s.Jar)
	if err != nil {
		return "", err
	}
	logInfo("page    :: status=%d size=%d", resp.Status, len(resp.Body))
	return string(resp.Body), nil
}

func (s *AWSWAFSession) fetchChallengeScript() (string, error) {
	headers := map[string]string{
		"Host":            extractHost(s.ChallengeScriptURL),
		"user-agent":      s.UserAgent,
		"accept":          "*/*",
		"accept-encoding": "gzip, deflate, br",
		"accept-language": "en-US,en;q=0.9",
		"sec-fetch-dest":  "script",
		"sec-fetch-mode":  "no-cors",
		"sec-fetch-site":  "cross-site",
		"referer":         fmt.Sprintf("https://%s/", s.Domain),
	}
	resp, err := DoRequest(s.ChallengeScriptURL, RequestOpts{
		Method:  "GET",
		Headers: headers,
		Proxy:   s.Proxy,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return "", err
	}
	if resp.Status != 200 {
		return "", fmt.Errorf("script returned %d", resp.Status)
	}
	return string(resp.Body), nil
}

func (s *AWSWAFSession) extractCryptoConfig(challengeScript string) (*CryptoConfig, error) {
	tmpFile, err := os.CreateTemp("", "awswaf_challenge_*.js")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(challengeScript); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()

	extractScript := findExtractScript()
	if extractScript == "" {
		return nil, fmt.Errorf("extract_config.js not found")
	}

	cmd := exec.Command("node", extractScript, tmpPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("node extraction failed: %v (stderr: %s)", err, stderr.String())
	}

	var result struct {
		Key           string            `json:"key"`
		Identifier    string            `json:"identifier"`
		TypeNames     map[string]string `json:"typeNames"`
		SignalVersion string            `json:"signalVersion"`
		Error         string            `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("parse extraction output: %w (raw: %s)", err, stdout.String())
	}
	if result.Error != "" {
		return nil, fmt.Errorf("extraction error: %s", result.Error)
	}
	if result.Key == "" {
		return nil, fmt.Errorf("no AES key found in challenge.js")
	}
	if result.Identifier == "" {
		return nil, fmt.Errorf("no identifier found in challenge.js")
	}

	keyBytes, err := hex.DecodeString(result.Key)
	if err != nil {
		return nil, fmt.Errorf("decode key hex: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("expected 32-byte key, got %d bytes", len(keyBytes))
	}

	config := &CryptoConfig{
		Key:           keyBytes,
		KeyHex:        result.Key,
		Identifier:    result.Identifier,
		TypeNames:     result.TypeNames,
		SignalVersion: result.SignalVersion,
	}
	if config.SignalVersion == "" {
		config.SignalVersion = "2.4.0"
	}

	logSuccess("crypto  :: id=%s key=%dB ver=%s types=%d",
		config.Identifier, len(config.Key), config.SignalVersion, len(config.TypeNames))
	return config, nil
}

func findExtractScript() string {
	candidates := []string{
		"extract_config.js",
		"go_AWS/extract_config.js",
	}

	if exePath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exePath), "extract_config.js"))
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		candidates = append(candidates, filepath.Join(filepath.Dir(thisFile), "extract_config.js"))
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func (s *AWSWAFSession) extractChallengeScriptURL(html string) (string, bool) {
	re := regexp.MustCompile(`(?:src\s*=\s*['"]|script\.src\s*=\s*['"])(https://[^'"]*\.sdk\.awswaf\.com/[^'"]*challenge\.js[^'"]*)['"]`)
	if m := re.FindStringSubmatch(html); m != nil {
		return m[1], true
	}

	re2 := regexp.MustCompile(`['"]?(https://[^'"]*awswaf\.com[^'"]*challenge[^'"]*\.js)['"]?`)
	if m := re2.FindStringSubmatch(html); m != nil {
		return m[1], true
	}

	return "", false
}

func (s *AWSWAFSession) extractCookieDomains(html string) []string {
	re := regexp.MustCompile(`awsWafCookieDomainList\s*=\s*\[([^\]]*)\]`)
	if m := re.FindStringSubmatch(html); m != nil {
		var domains []string
		for _, d := range strings.Split(m[1], ",") {
			d = strings.Trim(strings.TrimSpace(d), "'\"")
			if d != "" {
				domains = append(domains, d)
			}
		}
		return domains
	}
	return nil
}

func extractChallengeBase(scriptURL string) string {
	re := regexp.MustCompile(`^(.+)/challenge.*\.js`)
	if m := re.FindStringSubmatch(scriptURL); m != nil {
		return m[1]
	}
	u, err := url.Parse(scriptURL)
	if err != nil {
		return scriptURL
	}
	parts := strings.Split(u.Path, "/")
	u.Path = strings.Join(parts[:len(parts)-1], "/")
	return u.String()
}

func (s *AWSWAFSession) extractChallengeInputs(script string) *ChallengeInputs {
	difficultyRe := regexp.MustCompile(`parseInt\(['"](\d+)['"]\).*?parseInt\(['"](\d+)['"]\)`)
	var difficulty, memory int
	if m := difficultyRe.FindStringSubmatch(script); m != nil {
		fmt.Sscanf(m[1], "%d", &difficulty)
		fmt.Sscanf(m[2], "%d", &memory)
	}

	typeRe := regexp.MustCompile(`'(ha[0-9a-f]{60,})'`)
	challengeType := ""
	if m := typeRe.FindStringSubmatch(script); m != nil {
		challengeType = m[1]
	}

	b64Re := regexp.MustCompile(`'(eyJ[A-Za-z0-9+/=]{50,})'`)
	input := ""
	if m := b64Re.FindStringSubmatch(script); m != nil {
		input = m[1]
	}

	hmacRe := regexp.MustCompile(`['"]hmac['"]\]?\s*[=:]\s*['"]([A-Za-z0-9+/=]+)['"]`)
	hmacVal := ""
	if m := hmacRe.FindStringSubmatch(script); m != nil {
		hmacVal = m[1]
	}

	if hmacVal == "" && input != "" {
		inputIdx := strings.Index(script, input)
		if inputIdx > 0 {
			after := script[inputIdx+len(input):]
			hmacPosRe := regexp.MustCompile(`='([A-Za-z0-9+/]{30,50}=*)'`)
			if m := hmacPosRe.FindStringSubmatch(after[:min(len(after), 500)]); m != nil {
				hmacVal = m[1]
			}
		}
	}

	region := ""
	if input != "" {
		if decoded, err := base64.StdEncoding.DecodeString(input); err == nil {
			var inner struct {
				Region string `json:"region"`
			}
			if json.Unmarshal(decoded, &inner) == nil && inner.Region != "" {
				region = inner.Region
			}
		}
	}
	if region == "" {
		regionRe := regexp.MustCompile(`['"]region['"]\]?\s*[=:]\s*['"]([a-z0-9-]+)['"]`)
		if m := regionRe.FindStringSubmatch(script); m != nil {
			region = m[1]
		}
	}
	if region == "" && input != "" {
		inputIdx := strings.Index(script, input)
		if inputIdx > 0 {
			after := script[inputIdx+len(input):]
			regionPosRe := regexp.MustCompile(`='([a-z]{2}-[a-z]+-\d+)'`)
			if m := regionPosRe.FindStringSubmatch(after[:min(len(after), 500)]); m != nil {
				region = m[1]
			}
		}
	}

	logInfo("extract :: input=%s hmac=%s region=%s type=%s diff=%d mem=%d",
		truncate(input, 30), hmacVal, region, truncate(challengeType, 20), difficulty, memory)

	if challengeType == "" && input == "" {
		return nil
	}

	return &ChallengeInputs{
		Challenge: ChallengeData{
			Input:  input,
			Hmac:   hmacVal,
			Region: region,
		},
		ChallengeType: challengeType,
		Difficulty:    difficulty,
		Memory:        memory,
	}
}

func (s *AWSWAFSession) buildSignals() map[string]interface{} {
	now := time.Now()
	startTime := now.Add(-time.Duration(mrand.Intn(200)+100) * time.Millisecond)
	hardwareConcurrency := []int{4, 8, 12, 16}[mrand.Intn(4)]
	deviceMemory := []int{4, 8, 8, 16}[mrand.Intn(4)]
	dpr := []float64{1.0, 1.25, 1.5}[mrand.Intn(3)]

	gpus := []struct{ vendor, renderer string }{
		{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)"},
		{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"},
		{"Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"},
		{"Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)"},
	}
	gpu := gpus[mrand.Intn(len(gpus))]

	sigVersion := "2.4.0"
	if s.Crypto != nil && s.Crypto.SignalVersion != "" {
		sigVersion = s.Crypto.SignalVersion
	}

	signals := map[string]interface{}{
		"version": sigVersion,
		"navigator": map[string]interface{}{
			"userAgent":            s.UserAgent,
			"appCodeName":          "Mozilla",
			"appName":              "Netscape",
			"appVersion":           strings.TrimPrefix(s.UserAgent, "Mozilla/"),
			"language":             "en-US",
			"languages":            []string{"en-US", "en"},
			"platform":             "Win32",
			"product":              "Gecko",
			"productSub":           "20030107",
			"vendor":               "Google Inc.",
			"vendorSub":            "",
			"hardwareConcurrency":  hardwareConcurrency,
			"maxTouchPoints":       0,
			"cookieEnabled":        true,
			"onLine":               true,
			"deviceMemory":         deviceMemory,
			"pdfViewerEnabled":     true,
			"webdriver":            false,
		},
		"screen": map[string]interface{}{
			"width":       s.ScreenW,
			"height":      s.ScreenH,
			"availWidth":  s.ScreenW,
			"availHeight": s.ScreenH - 40,
			"colorDepth":  24,
			"pixelDepth":  24,
		},
		"window": map[string]interface{}{
			"innerWidth":       s.ScreenW,
			"innerHeight":      s.ScreenH - 117,
			"outerWidth":       s.ScreenW,
			"outerHeight":      s.ScreenH,
			"devicePixelRatio": dpr,
		},
		"tz": map[string]interface{}{
			"offset":   -300,
			"timezone": "America/New_York",
		},
		"time": map[string]interface{}{
			"start":   startTime.UnixMilli(),
			"elapsed": mrand.Intn(200) + 100,
		},
		"canvas": map[string]interface{}{
			"hash": generateCanvasHash(),
		},
		"gpu": map[string]interface{}{
			"vendor":         gpu.vendor,
			"renderer":       gpu.renderer,
			"extensions":     mrand.Intn(10) + 30,
			"viewportWidth":  s.ScreenW,
			"viewportHeight": s.ScreenH - 117,
		},
		"math": map[string]interface{}{
			"acos":  1.4473588658278522,
			"acosh": 709.889355822726,
			"asin":  0.12343746096704435,
			"asinh": 0.881373587019543,
			"atan":  0.4636476090008061,
			"atanh": 0.5493061443340549,
			"cos":   -0.4161468365471424,
			"cosh":  1.5430806348152437,
			"exp":   2.718281828459045,
			"expm1": 1.718281828459045,
			"log":   0.6931471805599453,
			"sin":   0.8414709848078965,
			"sinh":  1.1752011936438014,
			"sqrt":  1.4142135623730951,
			"tan":   -1.5574077246549023,
			"tanh":  0.7615941559557649,
		},
		"fonts": map[string]interface{}{
			"count": []int{42, 48, 55, 63}[mrand.Intn(4)],
			"hash":  fmt.Sprintf("%x", sha256Hash(fmt.Sprintf("fonts_%d_%d", s.ScreenW, mrand.Int()))),
		},
		"plugins": map[string]interface{}{
			"count": 5,
			"hash":  fmt.Sprintf("%x", sha256Hash("PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF")),
		},
		"perf": map[string]interface{}{
			"navigationStart": startTime.Add(-time.Duration(mrand.Intn(2000)+500) * time.Millisecond).UnixMilli(),
		},
		"stealth": map[string]interface{}{
			"webdriver":         false,
			"phantom":           false,
			"nightmare":         false,
			"selenium":          false,
			"domAutomation":     false,
			"chromiumBrowser":   true,
			"languageInconsist": false,
			"platformInconsist": false,
			"permissions":       true,
		},
		"batt": map[string]interface{}{
			"charging":        true,
			"chargingTime":    0,
			"dischargingTime": nil,
			"level":           []float64{0.85, 0.90, 0.95, 1.0}[mrand.Intn(4)],
		},
		"amazonUseragent": s.UserAgent,
		"client":          "Browser",
		"tVersion":        sigVersion,
		"id":              generateRandomID(),
		"errors":          []interface{}{},
	}

	return signals
}

func (s *AWSWAFSession) encodeSignals(signals map[string]interface{}) ([]interface{}, string, error) {
	if s.Crypto == nil {
		return nil, "", fmt.Errorf("crypto config not initialized")
	}

	jsonData, err := json.Marshal(signals)
	if err != nil {
		return nil, "", fmt.Errorf("signal marshal failed: %w", err)
	}

	crcVal := crc32.ChecksumIEEE(jsonData)
	checksum := fmt.Sprintf("%x", crcVal)

	plaintext := []byte(checksum + "#" + string(jsonData))

	block, err := aes.NewCipher(s.Crypto.Key)
	if err != nil {
		return nil, "", fmt.Errorf("aes cipher failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", fmt.Errorf("gcm failed: %w", err)
	}

	nonce := make([]byte, 12)
	rand.Read(nonce)

	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	tagSize := gcm.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	encryptedValue := base64.StdEncoding.EncodeToString(nonce) + "::" +
		hex.EncodeToString(tag) + "::" +
		hex.EncodeToString(ciphertext)

	signalEntry := map[string]interface{}{
		"name": s.Crypto.Identifier,
		"value": map[string]interface{}{
			"Present": encryptedValue,
		},
	}

	return []interface{}{signalEntry}, checksum, nil
}

func (s *AWSWAFSession) sendTelemetryRefresh() (*TelemetryResponse, error) {
	signals := s.buildSignals()
	signalsArray, checksum, err := s.encodeSignals(signals)
	if err != nil {
		return nil, err
	}

	existingToken := s.Jar.GetValue(s.Domain, "aws-waf-token")

	metrics := []map[string]interface{}{
		{"name": "TelemetryFormCycleBufferClearedCount", "value": 0, "unit": "Count"},
		{"name": "TelemetryNumberOfFormFields", "value": 0, "unit": "Count"},
		{"name": "TelemetryAcquisitionTime", "value": mrand.Intn(200) + 50, "unit": "Milliseconds"},
	}

	payload := map[string]interface{}{
		"client":   "Browser",
		"signals":  signalsArray,
		"checksum": checksum,
		"metrics":  metrics,
	}
	if existingToken != "" {
		payload["existing_token"] = existingToken
	}
	if s.SessionStorage != "" {
		payload["awswaf_session_storage"] = s.SessionStorage
	} else {
		payload["awswaf_session_storage"] = nil
	}

	payloadJSON, _ := json.Marshal(payload)
	telURL := s.ChallengeBaseURL + "/telemetry"
	logInfo("telemetry :: POST %s (%d bytes)", telURL, len(payloadJSON))

	resp, err := DoRequest(telURL, RequestOpts{
		Method:  "POST",
		Headers: s.challengeHeaders(),
		Body:    payloadJSON,
		Proxy:   s.Proxy,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("telemetry POST failed: %w", err)
	}

	if resp.Status != 200 {
		return nil, fmt.Errorf("telemetry returned status %d", resp.Status)
	}

	var telResp TelemetryResponse
	if err := json.Unmarshal(resp.Body, &telResp); err != nil {
		return nil, fmt.Errorf("telemetry parse failed: %w", err)
	}

	return &telResp, nil
}

func (s *AWSWAFSession) solveChallenge(ci *ChallengeInputs, checksum string) (string, error) {
	challengeType := ci.ChallengeType
	difficulty := ci.Difficulty
	memory := ci.Memory

	logInfo("type    :: %s  diff=%d  mem=%d", truncate(challengeType, 20), difficulty, memory)

	innerType := s.getInnerChallengeType(ci.Challenge.Input)
	logInfo("inner   :: %s", innerType)

	switch {
	case innerType == "NetworkBandwidth":
		return s.solveNetworkBandwidth(difficulty)
	case strings.HasPrefix(challengeType, "h72f957df"):
		return s.solveScryptHashcash(ci.Challenge.Input, checksum, difficulty, memory)
	case strings.HasPrefix(challengeType, "h7b0c470f"):
		return s.solveSHA2Hashcash(ci.Challenge.Input, checksum, difficulty)
	default:
		if difficulty >= 1 && difficulty <= 5 {
			return s.solveNetworkBandwidth(difficulty)
		}
		return s.solveScryptHashcash(ci.Challenge.Input, checksum, difficulty, memory)
	}
}

func (s *AWSWAFSession) getInnerChallengeType(input string) string {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "unknown"
	}
	var inner struct {
		ChallengeType string `json:"challenge_type"`
	}
	if err := json.Unmarshal(decoded, &inner); err != nil {
		return "unknown"
	}
	return inner.ChallengeType
}

func (s *AWSWAFSession) solveNetworkBandwidth(difficulty int) (string, error) {
	var bufSize int
	switch difficulty {
	case 1:
		bufSize = 1 * 0x400
	case 2:
		bufSize = 10 * 0x400
	case 3:
		bufSize = 100 * 0x400
	case 4:
		bufSize = 1 * 0x100000
	case 5:
		bufSize = 10 * 0x100000
	default:
		return "", fmt.Errorf("unsupported NetworkBandwidth difficulty: %d", difficulty)
	}

	buf := make([]byte, bufSize)
	solution := base64.StdEncoding.EncodeToString(buf)

	logInfo("bandwidth :: diff=%d buf=%d sol=%d", difficulty, bufSize, len(solution))
	return solution, nil
}

func (s *AWSWAFSession) solveScryptHashcash(input, checksum string, difficulty, memory int) (string, error) {
	startTime := time.Now()

	if difficulty < 0 || difficulty > 256 {
		return "", fmt.Errorf("invalid difficulty: %d", difficulty)
	}

	baseString := input + checksum
	salt := []byte(checksum)
	N := memory
	r := 8
	p := 1
	keyLen := 16

	for nonce := 0; ; nonce++ {
		password := []byte(baseString + fmt.Sprintf("%d", nonce))

		hash, err := scrypt.Key(password, salt, N, r, p, keyLen)
		if err != nil {
			return "", fmt.Errorf("scrypt failed: %w", err)
		}

		if hasLeadingZeroBits(hash, difficulty) {
			elapsed := time.Since(startTime)
			logSuccess("scrypt  :: solved in %v (nonce=%d)", elapsed, nonce)
			return fmt.Sprintf("%d", nonce), nil
		}

		if nonce > 0 && nonce%100 == 0 {
			logInfo("scrypt  :: nonce=%d (%.1fs)", nonce, time.Since(startTime).Seconds())
		}
	}
}

func (s *AWSWAFSession) solveSHA2Hashcash(input, checksum string, difficulty int) (string, error) {
	startTime := time.Now()
	baseString := input + checksum

	for nonce := 0; ; nonce++ {
		candidate := baseString + fmt.Sprintf("%d", nonce)
		hash := sha256.Sum256([]byte(candidate))

		if hasLeadingZeroBits(hash[:], difficulty) {
			elapsed := time.Since(startTime)
			logSuccess("sha2    :: solved in %v (nonce=%d)", elapsed, nonce)
			return fmt.Sprintf("%d", nonce), nil
		}

		if nonce > 0 && nonce%100000 == 0 {
			logInfo("sha2    :: nonce=%d (%.1fs)", nonce, time.Since(startTime).Seconds())
		}
	}
}

func hasLeadingZeroBits(hash []byte, n int) bool {
	for i := 0; i < n; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		if byteIdx >= len(hash) {
			return false
		}
		if hash[byteIdx]&(1<<uint(bitIdx)) != 0 {
			return false
		}
	}
	return true
}

func (s *AWSWAFSession) setWAFToken(token string) {
	s.WAFToken = token
	s.Jar.Set(s.Domain, "aws-waf-token", token)

	parts := strings.Split(s.Domain, ".")
	if len(parts) > 2 {
		parentDomain := strings.Join(parts[len(parts)-2:], ".")
		s.Jar.Set(parentDomain, "aws-waf-token", token)
	}

	logSuccess("token   :: %s", truncate(token, 80))
}

func (s *AWSWAFSession) VerifyToken() bool {
	headers := s.browserHeaders()
	existingCookies := headers["Cookie"]
	if !strings.Contains(existingCookies, "aws-waf-token") {
		if existingCookies != "" {
			headers["Cookie"] = existingCookies + "; aws-waf-token=" + s.WAFToken
		} else {
			headers["Cookie"] = "aws-waf-token=" + s.WAFToken
		}
	}

	resp, err := DoRequestFollowRedirects(s.TargetURL, RequestOpts{
		Method:  "GET",
		Headers: headers,
		Proxy:   s.Proxy,
		Timeout: 15 * time.Second,
	}, s.Jar)
	if err != nil {
		logFail("verify  :: %v", err)
		return false
	}

	logInfo("verify  :: status=%d size=%d", resp.Status, len(resp.Body))

	body := string(resp.Body)
	if resp.Status == 200 && !strings.Contains(body, "challenge.js") {
		logSuccess("verified -- page loads without challenge")
		return true
	}

	if resp.Status == 405 || resp.Status == 403 {
		logFail("token rejected (status %d)", resp.Status)
		return false
	}

	return resp.Status == 200
}

func generateRandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateCanvasHash() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sha256Hash(data string) []byte {
	h := sha256.Sum256([]byte(data))
	return h[:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
