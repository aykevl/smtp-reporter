package tlsrpt

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

type ReadError struct {
	Op  string
	Err error
}

func (e ReadError) Error() string {
	if e.Error == nil {
		return e.Op
	}
	return e.Op + ": " + e.Err.Error()
}

type Message struct {
	Domain    string
	Submitter string
	Report
}

type Report struct {
	OrganizationName string `json:"organization-name"`
	DateRange        struct {
		Start time.Time `json:"start-datetime"`
		End   time.Time `json:"end-datetime"`
	} `json:"date-range"`
	ContactInfo string   `json:"contact-info"`
	ReportID    string   `json:"report-id"`
	Policies    []Policy `json:"policies"`
}

type Policy struct {
	Policy struct {
		PolicyType   string   `json:"policy-type"`
		PolicyString []string `json:"policy-string"`
		PolicyDomain string   `json:"policy-domain"`
		MXHost       []string `json:"mx-host"`
	} `json:"policy"`
	Summary struct {
		TotalSuccessfulSessionCount int `json:"total-successful-session-count"`
		TotalFailureSessionCount    int `json:"total-failure-session-count"`
	} `json:"summary"`
	FailureDetails []struct {
		ResultType            string  `json:"result-type"`
		SendingMTAIP          net.IP  `json:"sending-mta-ip"`
		ReceivingMXHostname   string  `json:"receiving-mx-hostname"`
		ReceivingMXHELO       string  `json:"receiving-mx-helo"`
		ReceivingIP           net.IP  `json:"receiving-ip"`
		FailedSessionCount    int     `json:"failed-session-count"`
		AdditionalInformation url.URL `json:"additional-information"`
		FailureReasonCode     string  `json:"failure-reason-code"`
	} `json:"failure-details"`
}

func ReadMessage(mailMsg *mail.Message) (*Message, error) {
	message := &Message{
		Domain:    mailMsg.Header.Get("TLS-Report-Domain"),
		Submitter: mailMsg.Header.Get("TLS-Report-Submitter"),
	}
	if message.Domain == "" {
		return nil, ReadError{"empty TLS-Report-Domain field", nil}
	}
	if message.Submitter == "" {
		return nil, ReadError{"empty TLS-Report-Submitter field", nil}
	}

	mediaType, params, err := mime.ParseMediaType(mailMsg.Header.Get("Content-Type"))
	if err != nil {
		return nil, ReadError{"invalid Content-Type", err}
	}
	if mediaType != "multipart/report" {
		return nil, ReadError{"invalid media type", errors.New("expected media type to be 'multipart/report', got " + mediaType)}
	}
	if reportType := params["report-type"]; reportType != "tlsrpt" {
		return nil, ReadError{"invalid media type", errors.New("expected report type to be 'tlsrpt', got " + reportType)}
	}
	parts := multipart.NewReader(mailMsg.Body, params["boundary"])

	for {
		part, err := parts.NextPart()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, ReadError{"failed to read body part", err}
		}

		mediaType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return nil, ReadError{"failed to read multipart Content-Type", err}
		}
		if mediaType != "application/tlsrpt+json" && mediaType != "application/tlsrpt+gzip" {
			continue // the human readable part
		}

		if message.Report.ContactInfo != "" {
			return nil, ReadError{"more than one report included", nil}
		}

		var body io.Reader = part
		if part.Header.Get("Content-Transfer-Encoding") == "base64" {
			body = base64.NewDecoder(base64.StdEncoding, body)
		}
		if mediaType == "application/tlsrpt+gzip" {
			gzipBody, err := gzip.NewReader(body)
			if err != nil {
				return nil, ReadError{"failed to read gzip-compressed report body", err}
			}
			defer gzipBody.Close()
			body = gzipBody
		}

		err = json.NewDecoder(body).Decode(&message.Report)
		if err != nil {
			return nil, ReadError{"failed to read JSON report body", err}
		}

		// Check contact-info
		if index := strings.IndexByte(message.Report.ContactInfo, '@'); index < 0 {
			return nil, ReadError{"invalid or missing contact-info", nil}
		} else if message.Report.ContactInfo[index+1:] != message.Submitter {
			return nil, ReadError{"contact-info does not match TLS-Report-Submitter", nil}
		}
	}

	return message, nil
}
