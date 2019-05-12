// Dump the contents of EVTX files in readable format.
// Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/c73573ae-1c90-43a2-a65f-ad7501155956
// (c) 2019, igosha (2igosha@gmail.com)
package main

import (
	"igevtx"
	"fmt"
	"bufio"
	"os"
	"strings"
	"time"
	"io"
)

var out io.Writer

func init() {
	out = bufio.NewWriter(os.Stdout)
}

func normalizeNl(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, c := range s {
		if c == '\r' || c == '\n' {
			b.WriteRune(' ')
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func printEvent(t time.Time, num uint64, variable map[string]string) {
	fmt.Fprintf(out, "Record #%d %04d-%02d-%02dT%02d:%02d:%02dZ ", num, t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())

	for n, v := range variable {
		fmt.Fprintf(out, "%s:%s,", n, normalizeNl(v))
	}

	fmt.Fprintf(out, "\n")
}

func main() {
	for _, fname := range os.Args[1:] {
		err := igevtx.ParseEvtx(fname, printEvent)
		if err != nil {
			fmt.Printf("parseEvtx(%s) : %v\n", fname, err)
			os.Exit(2)
		}
	}
	switch out.(type) {
	case *bufio.Writer:
		out.(*bufio.Writer).Flush()
	}
}
