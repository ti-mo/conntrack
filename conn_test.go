package conntrack_test

import (
	"fmt"
	"log"
	"net/netip"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

func TestConnBufferSizes(t *testing.T) {
	c, err := conntrack.Dial(nil)
	require.NoError(t, err, "dialing conn")

	assert.NoError(t, c.SetReadBuffer(256))
	assert.NoError(t, c.SetWriteBuffer(256))

	require.NoError(t, c.Close(), "closing conn")
}

func ExampleConn_createUpdateFlow() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	// Set up a new Flow object using a given set of attributes.
	f := conntrack.NewFlow(
		17, 0,
		netip.MustParseAddr("2a00:1450:400e:804::200e"),
		netip.MustParseAddr("2a00:1450:400e:804::200f"),
		1234, 80, 120, 0,
	)

	// Send the Flow to the kernel.
	err = c.Create(f)
	if err != nil {
		log.Fatal(err)
	}

	f.Timeout = 240

	// Update the Flow's timeout to 240 seconds.
	err = c.Update(f)
	if err != nil {
		log.Fatal(err)
	}

	// Query the kernel based on the Flow's source/destination tuples.
	// Returns a new Flow object with its connection ID assigned by the kernel.
	qf, err := c.Get(f)
	if err != nil {
		log.Fatal(err)
	}

	// Print the result. The Flow has a timeout greater than 120 seconds.
	log.Print(qf)
}

func ExampleConn_dumpFilter() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	f1 := conntrack.NewFlow(
		6, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"),
		1234, 80, 120, 0x00ff, // Set a connection mark
	)

	f2 := conntrack.NewFlow(
		17, 0, netip.MustParseAddr("2a00:1450:400e:804::200e"), netip.MustParseAddr("2a00:1450:400e:804::200f"),
		1234, 80, 120, 0xff00, // Set a connection mark
	)

	_ = c.Create(f1)
	_ = c.Create(f2)

	// Dump all records in the Conntrack table that match the filter's mark/mask.
	df, err := c.DumpFilter(conntrack.Filter{Mark: 0xff00, Mask: 0xff00}, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Print the result. Only f2 is displayed.
	log.Print(df)
}

func ExampleConn_flush() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	// Evict all entries from the conntrack table in the current network namespace.
	err = c.Flush()
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleConn_flushFilter() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	f1 := conntrack.NewFlow(
		6, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"),
		1234, 80, 120, 0x00ff, // Set a connection mark
	)

	f2 := conntrack.NewFlow(
		17, 0, netip.MustParseAddr("2a00:1450:400e:804::200e"), netip.MustParseAddr("2a00:1450:400e:804::200f"),
		1234, 80, 120, 0xff00, // Set a connection mark
	)

	_ = c.Create(f1)
	_ = c.Create(f2)

	// Flush only the second flow matching the filter's mark/mask.
	err = c.FlushFilter(conntrack.Filter{Mark: 0xff00, Mask: 0xff00})
	if err != nil {
		log.Fatal(err)
	}

	// Getting f1 succeeds.
	_, err = c.Get(f1)
	if err != nil {
		log.Fatal(err)
	}

	// Getting f2 will fail, since it was flushed.
	_, err = c.Get(f2)
	if err != nil {
		log.Println("Flow f2 missing, as expected", err)
	}
}

func ExampleConn_delete() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	f := conntrack.NewFlow(
		6, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"),
		1234, 80, 120, 0,
	)

	// Create the Flow, will return err if unsuccessful.
	err = c.Create(f)
	if err != nil {
		log.Fatal(err)
	}

	// Delete the Flow based on its IP/port tuple, will return err if unsuccessful.
	err = c.Delete(f)
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleConn_listen() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	// Make a buffered channel to receive event updates on.
	evCh := make(chan conntrack.Event, 1024)

	// Listen for all Conntrack and Conntrack-Expect events with 4 decoder goroutines.
	// All errors caught in the decoders are passed on channel errCh.
	errCh, err := c.Listen(evCh, 4, append(netfilter.GroupsCT, netfilter.GroupsCTExp...))
	if err != nil {
		log.Fatal(err)
	}

	// Listen to Conntrack events from all network namespaces on the system.
	err = c.SetOption(netlink.ListenAllNSID, true)
	if err != nil {
		log.Fatal(err)
	}

	// Start a goroutine to print all incoming messages on the event channel.
	go func() {
		for {
			fmt.Println(<-evCh)
		}
	}()

	// Stop the program as soon as an error is caught in a decoder goroutine.
	log.Print(<-errCh)
}
