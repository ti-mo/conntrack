//+build integration

package conntrack

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
)

var ksyms []string

func TestMain(m *testing.M) {

	var err error

	if err = checkKmod(); err != nil {
		log.Fatal(err)
	}

	ksyms, err = getKsyms()
	if err != nil {
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
// Returns the Conn, the netns identifier and error.
func makeNSConn() (*Conn, int, error) {

	newns, err := netns.New()
	if err != nil {
		return nil, 0, fmt.Errorf("unexpected error creating network namespace: %s", err)
	}

	newConn, err := Dial(&netlink.Config{NetNS: int(newns)})
	if err != nil {
		return nil, 0, fmt.Errorf("unexpected error dialing namespaced connection: %s", err)
	}

	return newConn, int(newns), nil
}

// getKsyms gets a list of all symbols in the kernel. (/proc/kallsyms)
func getKsyms() ([]string, error) {

	f, err := ioutil.ReadFile("/proc/kallsyms")
	if err != nil {
		return nil, err
	}

	// Trim trailing newlines and split by newline
	content := strings.Split(strings.TrimSuffix(string(f), "\n"), "\n")
	out := make([]string, len(content))

	for i, l := range content {

		// Replace any tabs by spaces
		l = strings.Replace(l, "\t", " ", -1)

		// Get the third column
		out[i] = strings.Split(l, " ")[2]
	}

	return out, nil
}

// findKsym finds a given string in /proc/kallsyms. True means the string was found.
func findKsym(sym string) bool {

	for _, v := range ksyms {
		if v == sym {
			return true
		}
	}

	return false
}
