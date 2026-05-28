package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

const (
	banner  = `  aws-waf-solver`
	version = "1.0.0"
	credit  = "github.com/kareeen133 | dc: seb.ian (sec)"
)

var Debug bool

func main() {
	urlstr := flag.String("url", "https://test.com/sign", "Target URL protected by AWS WAF")
	retries := flag.Int("retries", 3, "Maximum solve attempts")
	debug := flag.Bool("debug", false, "Debug logging")
	flag.Parse()

	Debug = *debug

	for attempt := 1; attempt <= *retries; attempt++ {
		logPhase("attempt %d/%d", attempt, *retries)

		session := NewAWSWAFSession(*urlstr, "", nil)

		if session.Solve() {
			logSuccess("aws-waf-token obtained")
			logInfo("token   :: %s", truncate(session.WAFToken, 100))

			logPhase("verifying token")
			if session.VerifyToken() {
				logSuccess("bypass complete -- token verified")
				res, _ := json.MarshalIndent(session, "", "  ")
				fmt.Printf(string(res))
				os.Exit(0)
			} else {
				logWarn("token obtained but verification failed, retrying")
			}
		} else {
			logFail("attempt %d failed", attempt)
		}

		if attempt < *retries {
			delay := time.Duration(attempt*2) * time.Second
			logInfo("waiting %v before retry", delay)
			time.Sleep(delay)
		}
	}

	logFail("all %d attempts exhausted", *retries)
	os.Exit(1)
}

func logInfo(format string, args ...interface{}) {
	if Debug {
		msg := fmt.Sprintf(format, args...)
		log.Printf("\033[38;5;75m  >>\033[0m %s", msg)
	}
}

func logSuccess(format string, args ...interface{}) {
	if Debug {
		msg := fmt.Sprintf(format, args...)
		log.Printf("\033[38;5;84m  ++\033[0m %s", msg)
	}
}

func logFail(format string, args ...interface{}) {
	if Debug {
		msg := fmt.Sprintf(format, args...)
		log.Printf("\033[38;5;196m  --\033[0m %s", msg)
	}
}

func logWarn(format string, args ...interface{}) {
	if Debug {
		msg := fmt.Sprintf(format, args...)
		log.Printf("\033[38;5;214m  !!\033[0m %s", msg)
	}
}

func logPhase(format string, args ...interface{}) {
	if Debug {
		msg := fmt.Sprintf(format, args...)
		log.Printf("\n\033[38;5;129m  ── %s ──\033[0m", msg)
	}
}
