//+build integration

package conntrack

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
)

func TestMain(m *testing.M) {

	if err := checkKmod(); err != nil {
		log.Fatal(err)
	}

	rc := m.Run()
	os.Exit(rc)
}

// checkKmod checks if the kernel modules required for this test suite are loaded into the kernel.
func checkKmod() error {

	kmods := []string{
		"nf_conntrack_ipv4",
		"nf_conntrack_ipv6",
	}

	for _, km := range kmods {
		if _, err := os.Stat(fmt.Sprintf("/sys/module/%s", km)); os.IsNotExist(err) {
			return fmt.Errorf("required kernel module not loaded: %s", km)
		}
	}

	return nil
}

// makeNSConn creates a Conn in a new network namespace to use for testing.
func makeNSConn() (*Conn, error) {

	newns, err := netns.New()
	if err != nil {
		return nil, fmt.Errorf("unexpected error creating network namespace: %s", err)
	}
	defer newns.Close()

	newConn, err := Dial(&netlink.Config{NetNS: int(newns)})
	if err != nil {
		return nil, fmt.Errorf("unexpected error dialing namespaced connection: %s", err)
	}

	return newConn, nil
}
