package main

import (
	"errors"
	"io/ioutil"
	"log"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aykevl/smtp-reporter/tlsrpt"
)

var (
	performancePerDomain     = map[string]DomainResult{}
	performancePerDomainLock sync.Mutex
)

type DomainResult map[string]*SubmitterResult

type SubmitterResult struct {
	Domain           string
	OrganizationName string
	ContactInfo      string
	NumReports       int
	Start            time.Time
	End              time.Time
	Statistics       map[string]*Statistics
}

func (r *SubmitterResult) TotalCount() int {
	sum := 0
	for _, s := range r.Statistics {
		sum += s.TotalCount()
	}
	return sum
}

type Statistics struct {
	SuccessCount        int
	FailureCountReasons map[string]int
}

func (s *Statistics) FailureCount() int {
	if s.FailureCountReasons == nil {
		return 0
	}
	sum := 0
	for _, n := range s.FailureCountReasons {
		sum += n
	}
	return sum
}

func (s *Statistics) SuccessPercent() int {
	return s.SuccessCount * 100 / (s.SuccessCount + s.FailureCount())
}

func (s *Statistics) FailurePercent() int {
	return 100 - s.SuccessPercent()
}

func (s *Statistics) TotalCount() int {
	return s.SuccessCount + s.FailureCount()
}

func update(dir, dkimIdentifier string) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Println("failed to read mail directory")
		return
	}
	newPerformancePerDomain := map[string]DomainResult{}
	now := time.Now()
	for _, fileInfo := range files {
		if !fileInfo.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(dir, fileInfo.Name())
		message, err := readMessage(path, dkimIdentifier)
		if err != nil {
			log.Println("failed to read message:", err)
			continue
		}
		if message.DateRange.End.Before(now.Add(-time.Hour * 24 * 7)) {
			err := os.Remove(path)
			if err != nil {
				log.Printf("failed to remove %s: %s", path, err)
			} else {
				log.Printf("removed: %s", path)
			}
			continue
		}
		if _, ok := newPerformancePerDomain[message.Domain]; !ok {
			newPerformancePerDomain[message.Domain] = make(DomainResult, 1)
		}
		if _, ok := newPerformancePerDomain[message.Domain][message.Submitter]; !ok {
			newPerformancePerDomain[message.Domain][message.Submitter] = &SubmitterResult{}
		}
		sr := newPerformancePerDomain[message.Domain][message.Submitter]
		sr.NumReports++
		if sr.Start.IsZero() || sr.Start.After(message.DateRange.Start) {
			sr.Start = message.DateRange.Start
		}
		if sr.End.IsZero() || sr.End.Before(message.DateRange.End) {
			sr.End = message.DateRange.End
			sr.Domain = message.Submitter
			sr.OrganizationName = message.OrganizationName
			sr.ContactInfo = message.ContactInfo
		}
		for _, policy := range message.Policies {
			if sr.Statistics == nil {
				sr.Statistics = make(map[string]*Statistics)
			}
			if _, ok := sr.Statistics[policy.Policy.PolicyType]; !ok {
				sr.Statistics[policy.Policy.PolicyType] = &Statistics{}
			}
			statistics := sr.Statistics[policy.Policy.PolicyType]
			statistics.SuccessCount += policy.Summary.TotalSuccessfulSessionCount
			for _, details := range policy.FailureDetails {
				if statistics.FailureCountReasons == nil {
					statistics.FailureCountReasons = make(map[string]int)
				}
				statistics.FailureCountReasons[details.ResultType] += details.FailedSessionCount
			}
		}
	}

	performancePerDomainLock.Lock()
	performancePerDomain = newPerformancePerDomain
	performancePerDomainLock.Unlock()
}

func readMessage(path, dkimIdentifier string) (*tlsrpt.Message, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	mailMsg, err := mail.ReadMessage(f)
	if err != nil {
		return nil, err
	}

	if results := mailMsg.Header["Authentication-Results"]; len(results) == 0 {
		return nil, errors.New("no Authentication-Results header found for " + path)
	} else {
		if !strings.HasPrefix(results[len(results)-1], dkimIdentifier+";") {
			// Lazy DKIM check, assume it has been verified by OpenDKIM.
			return nil, errors.New("invalid Authentication-Results header in " + path)
		}
	}

	return tlsrpt.ReadMessage(mailMsg)
}
