package ipcfg

import (
	"fmt"
	"os"
	"os/exec"
)

func RunIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		return fmt.Errorf("error running ip command: %w", err)
	}
	return nil
}

func SetupInterface(ifaceName, ip string) error {
	err := RunIP("link", "set", "dev", ifaceName, "mtu", "1300")
	if err != nil {
		return fmt.Errorf("failed to set mtu: %w", err)
	}

	err = RunIP("addr", "add", ip, "dev", ifaceName)
	if err != nil {
		return fmt.Errorf("failed to set interface IP: %w", err)
	}

	err = RunIP("link", "set", "dev", ifaceName, "up")
	if err != nil {
		return fmt.Errorf("failed to start up the interface: %w", err)
	}

	fmt.Println("Interface setup done.")
	return nil
}
