package services

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/wahyuhadi/sast-to-faradaysec/models"
)

var (
	reponame_name = flag.String("r", "https://gitlab.com/unknown/unkown", "REPO name")
)

func Parsing_Semgrep_Output(file_input, file_output string) {
	flag.Parse()
	in, err := parsing_input(file_input)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	if len(in.Errors) != 0 {
		log.Println("Something error in file input semgrep")
		os.Exit(1)
	}

	severity := "high"
	var output models.Faraday
	for _, semgrep_data := range in.Results {
		desc := fmt.Sprintf("%s\n ```\n%s```", semgrep_data.Extra.Message, semgrep_data.Extra.Lines)
		if semgrep_data.Extra.Severity == "ERROR" {
			severity = "critical"
		}
		if semgrep_data.Extra.Severity == "WARNING" {
			severity = "high"
		}

		if semgrep_data.Extra.Severity == "INFO" {
			severity = "info"
		}
\

		assets := fmt.Sprintf("%s:%v:%v", semgrep_data.Path, semgrep_data.Start.Line, semgrep_data.Start.Col)

		output.IP = assets
		output.TemplateID = semgrep_data.CheckID
		output.Info.Name = desc
		output.Info.Severity = severity
		output.Host = *reponame_name
		output.Template = "technologies/tech-detect.yaml"
		output.Timestamp = time.Now()
		output.Type = "http"
		output.MatchedAt = *reponame_name
		output.TemplateURL = "https://github.com/projectdiscovery/nuclei-templates/blob/master/technologies/tech-detect.yaml"
		output.Info.Tags = []string{"tech"}
		output.MatcherStatus = true

		file, _ := json.Marshal(output)

		f, err := os.OpenFile(file_output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer f.Close()

		n, err := f.Write(file)
		if err != nil {
			fmt.Println(n, err)
		}

		if n, err = f.WriteString("\n"); err != nil {
			fmt.Println(n, err)
		}

	}

}

func parsing_input(file_input string) (*models.Semgrep, error) {
	jsonFile, err := os.Open(file_input)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var semgrep *models.Semgrep
	json.Unmarshal([]byte(byteValue), &semgrep)
	return semgrep, nil
}
