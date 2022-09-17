package models

type Semgrep struct {
	Errors []interface{} `json:"errors"`
	Paths  struct {
		Comment string   `json:"_comment"`
		Scanned []string `json:"scanned"`
	} `json:"paths"`
	Results []struct {
		CheckID string `json:"check_id"`
		End     struct {
			Col    int `json:"col"`
			Line   int `json:"line"`
			Offset int `json:"offset"`
		} `json:"end"`
		Extra struct {
			DataflowTrace struct {
				IntermediateVars []struct {
					End struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"end"`
					Path  string `json:"path"`
					Start struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"start"`
				} `json:"intermediate_vars"`
				TaintSource []struct {
					End struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"end"`
					Path  string `json:"path"`
					Start struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"start"`
				} `json:"taint_source"`
			} `json:"dataflow_trace"`
			Fingerprint string `json:"fingerprint"`
			IsIgnored   bool   `json:"is_ignored"`
			Lines       string `json:"lines"`
			Message     string `json:"message"`
			Metadata    struct {
				Category   string   `json:"category"`
				Confidence string   `json:"confidence"`
				Cwe        string   `json:"cwe"`
				License    string   `json:"license"`
				Owasp      []string `json:"owasp"`
				References []string `json:"references"`
				Technology []string `json:"technology"`
			} `json:"metadata"`
			Metavars struct {
				APP struct {
					AbstractContent string `json:"abstract_content"`
					End             struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"end"`
					Start struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"start"`
					UniqueID struct {
						Sid  int    `json:"sid"`
						Type string `json:"type"`
					} `json:"unique_id"`
				} `json:"$APP"`
				KNEX struct {
					AbstractContent string `json:"abstract_content"`
					End             struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"end"`
					Start struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"start"`
					UniqueID struct {
						Sid  int    `json:"sid"`
						Type string `json:"type"`
					} `json:"unique_id"`
				} `json:"$KNEX"`
				METHOD struct {
					AbstractContent string `json:"abstract_content"`
					End             struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"end"`
					Start struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"start"`
					UniqueID struct {
						Md5Sum string `json:"md5sum"`
						Type   string `json:"type"`
					} `json:"unique_id"`
				} `json:"$METHOD"`
				QUERY struct {
					AbstractContent string `json:"abstract_content"`
					End             struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"end"`
					Start struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"start"`
					UniqueID struct {
						Md5Sum string `json:"md5sum"`
						Type   string `json:"type"`
					} `json:"unique_id"`
				} `json:"$QUERY"`
				REQ struct {
					AbstractContent string `json:"abstract_content"`
					End             struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"end"`
					Start struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"start"`
					UniqueID struct {
						Sid  int    `json:"sid"`
						Type string `json:"type"`
					} `json:"unique_id"`
				} `json:"$REQ"`
				RES struct {
					AbstractContent string `json:"abstract_content"`
					End             struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"end"`
					Start struct {
						Col    int `json:"col"`
						Line   int `json:"line"`
						Offset int `json:"offset"`
					} `json:"start"`
					UniqueID struct {
						Sid  int    `json:"sid"`
						Type string `json:"type"`
					} `json:"unique_id"`
				} `json:"$RES"`
			} `json:"metavars"`
			Severity string `json:"severity"`
		} `json:"extra"`
		Path  string `json:"path"`
		Start struct {
			Col    int `json:"col"`
			Line   int `json:"line"`
			Offset int `json:"offset"`
		} `json:"start"`
	} `json:"results"`
	Version string `json:"version"`
}
