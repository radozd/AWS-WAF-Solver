package main

import (
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"os"
	"time"
)

const (
	banner = `  aws-waf-solver`
	version = "1.0.0"
	credit  = "github.com/kareeen133 | dc: seb.ian (sec)"
)

func main() {
	mrand.Seed(time.Now().UnixNano())

	targetURL := flag.String("url", "https://account.booking.com/sign-in", "Target URL protected by AWS WAF")
	proxy := flag.String("proxy", "", "Proxy in host:port:user:pass format")
	proxyFile := flag.String("proxy-file", "", "Path to proxy file (one per line)")
	maxRetries := flag.Int("retries", 3, "Maximum solve attempts")
	flag.Parse()

	log.SetFlags(0)
	fmt.Printf("\n\033[1;97m%s\033[0m \033[38;5;243mv%s\033[0m\n\n", banner, version)

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	logInfo("target  :: %s", *targetURL)

	var proxies []string
	if *proxyFile != "" {
		proxies = loadProxies(*proxyFile)
		logInfo("proxies :: %d loaded from %s", len(proxies), *proxyFile)
	}

	selectedProxy := *proxy
	if selectedProxy == "" && len(proxies) > 0 {
		selectedProxy = randomProxy(proxies)
	}
	if selectedProxy != "" {
		logInfo("proxy   :: %s", selectedProxy)
	} else {
		logWarn("proxy   :: none (direct connection)")
	}

	fmt.Println()

	for attempt := 1; attempt <= *maxRetries; attempt++ {
		logPhase("attempt %d/%d", attempt, *maxRetries)

		if attempt > 1 && len(proxies) > 0 {
			selectedProxy = randomProxy(proxies)
			logInfo("rotated :: %s", selectedProxy)
		}

		session := NewAWSWAFSession(*targetURL, selectedProxy, proxies)

		if session.Solve() {
			logSuccess("aws-waf-token obtained")
			logInfo("token   :: %s", truncate(session.WAFToken, 100))

			logPhase("verifying token")
			if session.VerifyToken() {
				logSuccess("bypass complete -- token verified")
				os.Exit(0)
			} else {
				logWarn("token obtained but verification failed, retrying")
			}
		} else {
			logFail("attempt %d failed", attempt)
		}

		if attempt < *maxRetries {
			delay := time.Duration(attempt*2) * time.Second
			logInfo("waiting %v before retry", delay)
			time.Sleep(delay)
		}
	}

	logFail("all %d attempts exhausted", *maxRetries)
	os.Exit(1)
}

func logInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("\033[38;5;75m  >>\033[0m %s", msg)
}

func logSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("\033[38;5;84m  ++\033[0m %s", msg)
}

func logFail(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("\033[38;5;196m  --\033[0m %s", msg)
}

func logWarn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("\033[38;5;214m  !!\033[0m %s", msg)
}

func logPhase(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("\n\033[38;5;129m  ── %s ──\033[0m", msg)
}
