//go:build integration

package conntrack

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

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

// Open a Netlink socket and set an option on it.
func TestConnDialSetOption(t *testing.T) {

	c, err := Dial(nil)
	require.NoError(t, err, "opening Conn")

	err = c.SetOption(netlink.ListenAllNSID, true)
	require.NoError(t, err, "setting SockOption")

	err = c.Close()
	require.NoError(t, err, "closing Conn")
}

// checkKmod checks if the kernel modules required for this test suite are loaded into the kernel.
// Since around 4.19, conntrack is a single module, so only warn about _ipv4/6 when that one
// is not loaded.
func checkKmod() error {

	kmods := []string{
		"nf_conntrack_ipv4",
		"nf_conntrack_ipv6",
	}

	if _, err := os.Stat("/sys/module/nf_conntrack"); os.IsNotExist(err) {
		// Fall back to _ipv4/6 if nf_conntrack is missing.
		for _, km := range kmods {
			if _, err := os.Stat(fmt.Sprintf("/sys/module/%s", km)); os.IsNotExist(err) {
				return fmt.Errorf("missing kernel module %s and module nf_conntrack", km)
			}
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
