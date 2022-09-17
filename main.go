package main

import (
	"flag"
	"os"

	"log"

	"github.com/wahyuhadi/sast-to-faradaysec/services"
)

var (
	output_name = "Faraday-output.json"
	input       = flag.String("i", "", "location file")
	output      = flag.String("o", output_name, "output location")
)

func main() {
	flag.Parse()
	if *input == "" {
		log.Println("No input location ")
		os.Exit(1)
	}
	services.Parsing_Semgrep_Output(*input, *output)

}
