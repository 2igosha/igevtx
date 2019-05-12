# igevtx
**Windows EVTX file format parser: an experiment in Go**

## Sources: 
go get github.com/2igosha/igevtx/dump_evtx

## Usage:
dump_evtx list_of_evtx_filenames

The parser is wrapped in a package and can be used with a callback function:

```import (
	"github.com/2igosha/igevtx/igevtx"
	...
	)
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
```

