package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type rule struct {
	HostIp   string `json:"ip"`
	HostPort int    `json:"port"`
	Chain    string
}

type iptablesService struct {
	IptablesPath    string
	DockerInterface string
	Rules           map[string][]rule
	chains          map[string]bool
	readOnly        bool
}

func loadIptablesConfig(configPath string) (*iptablesService, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	service := iptablesService{
		chains:   make(map[string]bool),
		readOnly: len(os.Getenv("READ_ONLY")) > 0,
	}
	err = decoder.Decode(&service)
	if err != nil {
		return nil, err
	}
	if len(service.IptablesPath) == 0 {
		service.IptablesPath = "/sbin/iptables"
	}
	for _, cont := range service.Rules {
		for _, rule := range cont {
			service.chains[rule.Chain] = true
		}
	}
	log.Printf("Loaded %d rules, %d chains\n", len(service.Rules), len(service.chains))
	return &service, nil
}

func (s *iptablesService) call(args ...string) error {
	log.Printf("%s %s\n", s.IptablesPath, strings.Join(args, " "))
	if s.readOnly {
		return nil
	}
	out, err := exec.Command(s.IptablesPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s (%s)", out, err.Error())
	}
	return nil
}

func getShortId(id string) string {
	return id[:12]
}

func (s *iptablesService) removeContainerRules(id string) error {
	log.Printf("Remove container: %s\n", id)
	if s.readOnly {
		return nil
	}
	re := regexp.MustCompile(`^(\d+).*\[` + getShortId(id) + `\]`)
	for chain, _ := range s.chains {
		out, err := exec.Command(s.IptablesPath, "-t", "nat", "-L", chain, "-n", "--line-numbers").CombinedOutput()
		if err != nil {
			return fmt.Errorf("Can't get chain %s rules list %s (%s)", chain, err.Error(), out)
		}
		matches := re.FindAllStringSubmatch(string(out), -1)
		for _, rule := range matches {
			err := s.call("-t", "nat", "-D", chain, rule[1])
			if err != nil {
				return fmt.Errorf("Can't delete rule %s from chain %s (%s)", rule[1], chain, err.Error())
			}
		}
	}
	return nil
}

func (s *iptablesService) addContainerRules(cont *container) error {
	log.Println("Add container: ", cont.Name)
	for _, rule := range s.Rules[cont.Name] {
		log.Printf("Add container: %s %+v\n", cont.Name, rule)
		for contPort, binds := range cont.Ports {
			for _, bind := range binds {
				if bind.Port == rule.HostPort {
					protocol := "tcp"
					if strings.HasSuffix(contPort, "/udp") {
						protocol = "udp"
					}
					hostIp := rule.HostIp
					if len(rule.HostIp) == 0 {
						hostIp = "0.0.0.0/0"
					}
					err := s.call("-t", "nat", "-A", rule.Chain, "-d", hostIp, "!", "-i", s.DockerInterface,
						"-p", protocol, "-m", protocol,
						"--dport", strconv.FormatInt(int64(bind.Port), 10), "-j", "DNAT",
						"--to-destination", fmt.Sprintf("%s:%s", cont.Ip, contPort[:len(contPort)-4]),
						"-m", "comment", "--comment", fmt.Sprintf("'Docker %s[%s]'", cont.Name, getShortId(cont.Id)))
					if err != nil {
						log.Println(err)
					}
				}
			}
		}
	}
	return nil
}

func (s *iptablesService) rebuildFirewall(containers containerMap) error {
	for chain, _ := range s.chains {
		err := s.call("-t", "nat", "-N", chain) // try to create a chain if it does not exist create it
		if err != nil {
			err := s.call("-t", "nat", "-F", chain)
			if err != nil {
				return fmt.Errorf("Can't create chain %s (%s)", chain, err.Error())
			}
		}
	}
	for _, cont := range containers {
		err := s.addContainerRules(cont)
		if err != nil {
			return err
		}
	}
	return nil
}
