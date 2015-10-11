package main

import (
	"log"
	"strconv"
	"sync"

	"github.com/samalba/dockerclient"
)

type portBind struct {
	Ip   string
	Port int
}

type container struct {
	Id    string
	Ip    string
	Name  string
	Ports map[string][]portBind
}

type containerMap map[string]*container

type dockerService struct {
	docker     *dockerclient.DockerClient
	iptables   *iptablesService
	containers containerMap
	contSync   sync.Mutex
}

func createDockerService(socket, configPath string) (*dockerService, error) {
	docker, err := dockerclient.NewDockerClient(socket, nil)
	if err != nil {
		return nil, err
	}
	iptables, err := loadIptablesConfig(configPath)
	if err != nil {
		return nil, err
	}
	return &dockerService{
		docker:     docker,
		iptables:   iptables,
		containers: make(containerMap),
	}, nil
}

func (s *dockerService) startContainer(id string) {
	s.contSync.Lock()
	_, present := s.containers[id]
	if present { // out of sync - update all list
		s.contSync.Unlock()
		s.updateContainerList()
	} else {
		defer s.contSync.Unlock()

		cont, err := s.getContainer(id)
		if err != nil {
			return
		}
		s.containers[id] = cont
		err = s.iptables.addContainerRules(cont)
		if err != nil {
			log.Println(err)
		}
	}
}

func (s *dockerService) dieContainer(id string) {
	s.contSync.Lock()
	_, present := s.containers[id]
	if present {
		err := s.iptables.removeContainerRules(id)
		if err == nil {
			delete(s.containers, id)
			s.contSync.Unlock()
			return
		} else {
			log.Println(err)
		}
	}
	s.contSync.Unlock()
	s.updateContainerList()
}

func (s *dockerService) dockerEvent(event *dockerclient.Event, ec chan error, args ...interface{}) {
	log.Printf("Received event: %#v\n", *event)
	switch event.Status {
	case "start":
		s.startContainer(event.Id)
		break
	case "die":
		s.dieContainer(event.Id)
		break
	}
}

func (s *dockerService) listen() {
	s.docker.StartMonitorEvents(s.dockerEvent, nil)
}

func (s *dockerService) getContainer(id string) (*container, error) {
	info, err := s.docker.InspectContainer(id)
	if err != nil {
		return nil, err
	}
	cont := container{
		Id:    info.Id,
		Name:  info.Name[1:],
		Ip:    info.NetworkSettings.IPAddress,
		Ports: make(map[string][]portBind),
	}
	for p, ports := range info.NetworkSettings.Ports {
		for _, bind := range ports {
			port, _ := strconv.Atoi(bind.HostPort)
			cont.Ports[p] = append(cont.Ports[p], portBind{
				Ip:   bind.HostIp,
				Port: port,
			})
		}
	}
	return &cont, nil
}

func (s *dockerService) updateContainerList() error {
	containers, err := s.docker.ListContainers(false, false, "")
	if err != nil {
		return err
	}
	s.contSync.Lock()
	defer s.contSync.Unlock()
	s.containers = make(map[string]*container)

	for _, c := range containers {
		cont, err := s.getContainer(c.Id)
		if err == nil {
			s.containers[c.Id] = cont
		} else {
			log.Println(err)
		}
	}
	return s.iptables.rebuildFirewall(s.containers)
}
