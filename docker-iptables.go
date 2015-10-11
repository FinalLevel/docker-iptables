package main

import (
	"flag"
	"log"
	"net/http"
	"os"
)

func main() {
	var (
		socket     = flag.String("s", "unix:///var/run/docker.sock", "docker socket url")
		configPath = flag.String("c", "config/iptables.json", "iptables config path")
	)
	flag.Parse()
	dockerService, err := createDockerService(*socket, *configPath)
	if err != nil {
		log.Fatal(err)
	}
	dockerService.listen()

	err = dockerService.updateContainerList()
	if err != nil {
		log.Fatal(err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "5152"
	}
	http.ListenAndServe(":"+port, nil)
}
