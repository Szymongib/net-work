package main

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

// TODO: allow them to be in single file
type config struct {
	Static BeeConfig
	Swarm  SwarmConfig
}

// TODO: some defaults, env names etc
// TODO: better name
type BeeConfig struct {
	ListenAddr string
	IfaceIP    string
	IfaceName  string
}

// TODO: maybe some cool names
type SwarmConfig struct {
	Peers []Peer
}

func LoadConfig(staticCfgPath, swarmPath string) (BeeConfig, SwarmConfig, error) {
	staticCfg, err := parseConfig[BeeConfig](staticCfgPath, BeeConfig{})
	if err != nil {
		return BeeConfig{}, SwarmConfig{}, errors.Wrap(err, "failed to read static config")
	}

	swarmConfig, err := parseConfig[SwarmConfig](swarmPath, SwarmConfig{})
	if err != nil {
		return BeeConfig{}, SwarmConfig{}, errors.Wrap(err, "failed to read swarm config")
	}

	return staticCfg, swarmConfig, nil
}

func parseConfig[T](filePath string, defaults T) (T, error) {
	var fromFile T
	if filePath != "" {
		raw, err := ioutil.ReadFile(filePath)
		if err != nil {
			// TODO: zero values
			return fromFile, errors.Wrap(err, "failed to read file")
		}
		err = yaml.Unmarshal(raw, &fromFile)
		if err != nil {
			return fromFile, errors.Wrap(err, "failed to YAML unmarshal config")
		}
	}

	// TODO: go through each filed in defaults and unmarshalled and set appropriately
	// TODO: go through envs
	// TODO: respect flags?

	return fromFile, nil
}
