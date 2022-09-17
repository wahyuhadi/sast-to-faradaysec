package models

import "time"

type Faraday struct {
	Template    string `json:"template"`
	TemplateURL string `json:"template-url"`
	TemplateID  string `json:"template-id"`
	Info        struct {
		Name      string      `json:"name"`
		Author    []string    `json:"author"`
		Tags      []string    `json:"tags"`
		Reference interface{} `json:"reference"`
		Severity  string      `json:"severity"`
	} `json:"info"`
	MatcherName   string      `json:"matcher-name"`
	Type          string      `json:"type"`
	Host          string      `json:"host"`
	MatchedAt     string      `json:"matched-at"`
	IP            string      `json:"ip"`
	Timestamp     time.Time   `json:"timestamp"`
	CurlCommand   string      `json:"curl-command"`
	MatcherStatus bool        `json:"matcher-status"`
	MatchedLine   interface{} `json:"matched-line"`
}
