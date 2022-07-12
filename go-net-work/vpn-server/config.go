package main

import (
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

// TODO: allow them to be in single file
type config struct {
	Bee   BeeConfig   `yaml:"bee"`
	Swarm SwarmConfig `yaml:"swarm"`
}

// TODO: some defaults, env names etc
// TODO: better name
type BeeConfig struct {
	ListenAddr string `yaml:"listenAddr"`
	IfaceIP    string `yaml:"ifaceIP"`
	IfaceName  string `yaml:"ifaceName"`
}

// TODO: maybe some cool names
type SwarmConfig struct {
	Peers []Peer `yaml:"peers"`
}

func LoadConfig(staticCfgPath, swarmPath string) (BeeConfig, SwarmConfig, error) {
	staticCfg, err := parseConfig[config](staticCfgPath, config{})
	if err != nil {
		return BeeConfig{}, SwarmConfig{}, errors.Wrap(err, "failed to read static config")
	}

	swarmConfig, err := parseConfig[config](swarmPath, config{})
	if err != nil {
		return BeeConfig{}, SwarmConfig{}, errors.Wrap(err, "failed to read swarm config")
	}

	return staticCfg.Bee, swarmConfig.Swarm, nil
}

func parseConfig[T any](filePath string, defaults T) (T, error) {
	var fromFile T
	if filePath != "" {
		raw, err := ioutil.ReadFile(filePath)
		if err != nil {
			// TODO: zero values
			return fromFile, errors.Wrap(err, "failed to read file")
		}
		fmt.Println(string(raw))

		err = yaml.Unmarshal(raw, &fromFile)
		if err != nil {
			return fromFile, errors.Wrap(err, "failed to YAML unmarshal config")
		}
	} else {
		fmt.Println("FILE PATH EMPTY")
	}

	// TODO: go through each filed in defaults and unmarshalled and set appropriately
	// TODO: go through envs
	// TODO: respect flags?

	return fromFile, nil
}
