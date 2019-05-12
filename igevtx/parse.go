// Parse the contents of the EVTX files.
// Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/c73573ae-1c90-43a2-a65f-ad7501155956
// (c) 2019, igosha (2igosha@gmail.com)
package igevtx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

// Callback type for ParseEvtx, gets the timestamp, record number and values for each event log record
type EventHandler func(when time.Time, num uint64, variable map[string]string)

type parser struct {
	t     templates
	ct    *template
	xpath []string	// virtual path in the xml tree
	attr  string	// current attribute name
	evtname	string	// cached name used for proper attr naming
	variable map[string]string	// current substitutions within the template, valid for one record
}

type evtxHeader struct {
	Magic           [8]byte
	ChunksAllocated uint64
	ChunksUsed      uint64
	Checksum        uint64
	Flags           uint32
	Version         uint32
	Fsize           uint64
	_               [0x1000 - 0x30]byte
}

type chunkHeader struct {
	Magic    [8]byte
	FirstNum uint64
	LastNum  uint64
	_        uint64
	_        uint64
	Sz       uint32
	_        [0x80 - 0x2C]byte
	_        [0x200 - 0x80]byte
}

type recHeader struct {
	Magic     uint32
	Sz        uint32
	Num       uint64
	Timestamp uint64
}

type guid struct {
	D1 uint32
	W1 uint16
	W2 uint16
	B1 [8]byte
}

const recHeaderSize = (4 + 4 + 8 + 8)

func convertUnicodeString(buf []uint16) (string, error) {
	// The only reason for this function to exist is
	// because the conversion using encoding/utf16 is slower
	var b strings.Builder
	for _, w := range buf {
		var msb byte
		var mask byte

		if w <= 0x7F {
			b.WriteByte(byte(w))
			continue
		}
		var charLen uint = 2
		msb |= 0x80 + 0x40
		mask = 0xFF
		if w > 0x7FF {
			charLen++
			msb |= 0x20
			mask = 0x1F
		}
		if w > 0xFFFF {
			charLen++
			msb |= 0x10
			mask = 0x0F
		}
		b.WriteByte(msb | (byte(w) & mask))
		var i uint
		for i = 1; i < charLen; i++ {
			b.WriteByte(byte(0x80 | (w >> (6 * (charLen - i - 1)))))
		}
	}
	return b.String(), nil
}

func convertUnicodeString2(buf []uint16) (string, error) {
	// And here is the slower version
	runes := utf16.Decode(buf)
	return string(runes), nil
}

func readPrefixedUnicodeString(rd io.ReadSeeker, nullTerm bool) (string, error) {
	var cnt uint16
	var err error

	if cnt, err = readWord(rd); err != nil {
		return "", err
	}
	buf := make([]uint16, cnt)
	if err = readWordN(rd, buf); err != nil {
		return "", err
	}
	if nullTerm {
		if _, err = rd.Seek(2, io.SeekCurrent); err != nil {
			return "", err
		}
	}
	return convertUnicodeString(buf)
}

func readName(rd io.ReadSeeker) (string, error) {
	var off uint32
	var prev int64
	var err error

	off, err = readDword(rd)
	if err != nil {
		return "", err
	}
	prev, err = rd.Seek(0, io.SeekCurrent)
	// fmt.Printf("readName() off = %08X, curr at %08X\n", off, prev)

	if prev != int64(off) {
		if _, err = rd.Seek(int64(off), io.SeekStart); err != nil {
			return "", err
		}
		defer rd.Seek(prev, io.SeekStart)
	}

	_, err = readDword(rd)
	if err != nil {
		return "", err
	}
	if _, err = readWord(rd); err != nil {
		return "", err
	}

	return readPrefixedUnicodeString(rd, true)
}

func (p *parser) OpenStartElement(rd io.ReadSeeker, hasAttrs bool) error {
	var err error

	_, err = readWord(rd)
	if err != nil {
		return err
	}
	_, err = readDword(rd)
	if err != nil {
		return err
	}
	s, err := readName(rd)
	if err != nil {
		return err
	}
	//fmt.Printf("*** OpenStartElement: %v\n", s)
	if hasAttrs {
		if _, err = readDword(rd); err != nil {
			return err
		}
		// fmt.Printf(" attrs: %v\n", d)
	}

	p.xpath = append(p.xpath, s)
	p.attr = ""
	return nil
}

func (p *parser) CloseStartElement(rd io.ReadSeeker) error {
	p.attr = ""
	return nil
}

func (p *parser) CloseElement(rd io.ReadSeeker) error {
	if len(p.xpath) > 0 {
		p.xpath = p.xpath[0 : len(p.xpath)-1]
	}
	p.attr = ""
	//fmt.Printf("CloseElement\n")
	return nil
}

func (p *parser) AttributeToken(rd io.ReadSeeker) error {
	var s string
	var err error
	if s, err = readName(rd); err != nil {
		return err
	}
	p.attr = s
	return nil
}

func (p *parser) SubstitutionToken(rd io.ReadSeeker) error {
	var err error
	var id uint16
	var t uint8

	if id, err = readWord(rd); err != nil {
		return err
	}
	if t, err = readByte(rd); err != nil {
		return err
	}
	if t == 0 {
		if t, err = readByte(rd); err != nil {
			return err
		}
	}

	p.ct.subst[id] = *p.GetProperKeyName(&p.attr)
	// fmt.Printf("*** %v::%s = param %v / type %v\n", p.xpath, p.attr, id, t)
	return nil
}

var estr = ""

func (p *parser) GetProperKeyName(s *string) *string {
	if p.attr == "" {
		if len(p.xpath) > 1 && p.xpath[len(p.xpath)-1] == "Data" && p.xpath[len(p.xpath)-2] == "EventData" && p.evtname != "" {
			return &p.evtname
		} else if len(p.xpath) > 0 {
			return &p.xpath[len(p.xpath)-1]
		} else {
			return &estr
		}
	} else {
		return s
	}
}

func (p *parser) ValueTextToken(rd io.ReadSeeker) error {
	var s string
	var err error

	if _, err = readByte(rd); err != nil {
		return err
	}
	if s, err = readPrefixedUnicodeString(rd, false); err != nil {
		return err
	}
	if len(p.xpath) > 1 &&
		p.attr == "Name" &&
		p.xpath[len(p.xpath)-1] == "Data" &&
		p.xpath[len(p.xpath)-2] == "EventData" {
			p.evtname = s
	} else {
		p.ct.fixed[*p.GetProperKeyName(&p.attr)] = "'" + s + "'"
	}
	// fmt.Printf("*** %v::%s = %q\n", p.xpath, p.attr, s)
	return nil
}

type template struct {
	fixed map[string]string // name - value
	subst map[uint16]string // id	- name
}

type templates map[uint32]*template

func newTemplates() templates {
	t := make(templates)
	return t
}

func newParser() *parser {
	p := new(parser)
	p.Reset()
	return p
}

func (p *parser) Reset() {
	p.t = newTemplates()
	p.xpath = make([]string, 0, 16)
}

func (p *parser) ResetPerRecord() {
	p.variable = make(map[string]string)
	p.ct = nil
}

func newTemplate() *template {
	t := new(template)
	t.fixed = make(map[string]string)
	t.subst = make(map[uint16]string)
	return t
}

func timeFromFileTime(ft uint64) time.Time {
	// Convert from MS FileTime
	return time.Unix((int64(ft)-11644473600000*10000)/10000000, 0).UTC()
}

func (p *parser) TemplateInstance(rd io.ReadSeeker) error {
	var b byte
	var err error
	var id uint32
	var d uint32
	var narg uint32
	var w uint16
	var sd int32
	var q uint64
	var sq int64
	var v string

	if b, err = readByte(rd); err != nil || b != 0x01 {
		return fmt.Errorf("unable to get first 0x01")
	}
	if id, err = readDword(rd); err != nil {
		return err
	}
	if d, err = readDword(rd); err != nil {
		return err
	}
	if narg, err = readDword(rd); err != nil {
		return err
	}

	// fmt.Printf("===== Template %08X ==== \n", id)
	t, ok := p.t[id]
	if !ok {
		// New template
		var tlen uint32

		lid := make([]byte, 16)
		if _, err = io.ReadFull(rd, lid); err != nil {
			return err
		}
		if tlen, err = readDword(rd); err != nil {
			return err
		}
		// fmt.Printf("template body, len %08X\n", tlen)

		t = newTemplate()
		p.t[id] = t

		pos, _ := rd.Seek(0, io.SeekCurrent)
		p.ct = t
		// fmt.Printf("=== %08X\n", pos);
		if err = p.parseBinXML(rd); err != nil {
			fmt.Printf("Parse error %v\n", err)
			return err
		}

		// fmt.Printf("===\n");

		// skip exactly tlen bytes
		if _, err = rd.Seek(pos+int64(tlen), io.SeekStart); err != nil {
			return err
		}

		if narg, err = readDword(rd); err != nil {
			return err
		}
	}

	for k, v := range t.fixed {
		p.variable[k] = v
	}

	argMap := make([]uint16, 2*narg)
	if err = readWordN(rd, argMap); err != nil {
		return err
	}

	var i uint16
	for i = 0; i < uint16(narg); i++ {
		atype := argMap[i*2+1]
		alen := argMap[i*2]
		// fmt.Printf("arg len 0x%08X type 0x%08X\n", alen, atype)
		switch atype {
		case 0x01: /* utf-16 string */
			if alen < 2 {
				break
			}
			buf := make([]uint16, alen/2)
			if err = readWordN(rd, buf); err != nil {
				return err
			}
			s, err := convertUnicodeString(buf)
			if s[len(s)-1] == 0 {
				s = s[:len(s)-1]
			}
			if err != nil {
				return err
			}
			v = "'"
			v += s
			v += "'"
		case 0x02: /* char string */
			buf := make([]byte, alen)
			if _, err = io.ReadFull(rd, buf); err != nil {
				return err
			}
			if len(buf) > 0 && buf[len(buf)-1] == 0x00 {
				buf = buf[:len(buf)-1]
			}
			v = "'" + string(buf) + "'"
		case 0x04: /* uint8_t */
			if b, err = readByte(rd); err != nil {
				return err
			}
			v = fmt.Sprintf("%02d", b)
		case 0x06: /* uint16_t */
			if w, err = readWord(rd); err != nil {
				return err
			}
			v = fmt.Sprintf("%04d", w)
		case 0x07: /* int32_t */
			if sd, err = readInt32(rd); err != nil {
				return err
			}
			v = fmt.Sprintf("%08d", sd)
		case 0x08: /* uint32_t */
			if d, err = readDword(rd); err != nil {
				return err
			}
			v = fmt.Sprintf("%08d", d)
		case 0x09: /* int64_t */
			if sq, err = readInt64(rd); err != nil {
				return err
			}
			v = fmt.Sprintf("%016d", sq)
		case 0x0A: /* uint64_t */
			if q, err = readQword(rd); err != nil {
				return err
			}
			v = fmt.Sprintf("%016d", q)
		case 0x0D: /* bool */
			if alen < 1 {
				return fmt.Errorf("bool is too small")
			}
			if b, err = readByte(rd); err != nil {
				return err
			}
			if b == 0 {
				v = "false"
			} else {
				v = "true"
			}
			if alen > 1 {
				rd.Seek(int64(alen)-1, io.SeekCurrent)
			}
		case 0x00, 0x0E: /* binary */
			buf := make([]byte, alen)
			if _, err = io.ReadFull(rd, buf); err != nil {
				return err
			}
			for _, b := range buf {
				v += fmt.Sprintf("%02X", b)
			}
		case 0x0C: /* Real64 */
			var	r64	float64
			if err = binary.Read(rd, binary.LittleEndian, &r64); err != nil {
				return err
			}
			v = fmt.Sprintf("%f", r64)
		case 0x0F: /* GUID */
			var g guid
			if err = binary.Read(rd, binary.LittleEndian, &g); err != nil {
				return err
			}
			v = fmt.Sprintf("%08X-%02X-%02X-%02X%02X%02X%02X%02X%02X%02X%02X",
				g.D1, g.W1, g.W2,
				g.B1[0], g.B1[1], g.B1[2], g.B1[3],
				g.B1[4], g.B1[5], g.B1[6], g.B1[7])

		case 0x11: /* FileTime */
			if q, err = readQword(rd); err != nil {
				return err
			}

			t := timeFromFileTime(q)
			v = fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second()) + "Z"
		case 0x12: /* SysTime */
			var st	[8]uint16
			if err = readWordN(rd, st[:]); err != nil {
				return err
			}
			v = fmt.Sprintf("SYSTI%04d-%02d-%02dT%02d:%02d:%02d", st[0], st[1], st[3], st[4], st[5], st[6]) + "Z"
		case 0x13: /* SID */
			sid := make([]byte, 2+6)
			if _, err = io.ReadFull(rd, sid); err != nil {
				return err
			}
			q = 0
			for i := 0; i < 6; i++ {
				q <<= 8
				q |= uint64(sid[2+i])
			}
			v = fmt.Sprintf("S-%d-%d", uint(sid[0]), q)
			for i := 2 + 6; i+4 <= int(alen); i += 4 {
				if d, err = readDword(rd); err != nil {
					return err
				}
				v += fmt.Sprintf("-%d", d)
			}
		case 0x14: /* HexInt32 */
			if d, err = readDword(rd); err != nil {
				return err
			}
			v = fmt.Sprintf("0x%08X", d)
		case 0x15: /* HexInt64 */
			if q, err = readQword(rd); err != nil {
				return err
			}
			v = fmt.Sprintf("0x%016X", q)
		case 0x21: /* BinXml */
			pos, err := rd.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}
			p.ct = nil // so that we don't try to save
			// the fields in the upper level template
			if err = p.parseBinXML(rd); err != nil {
				return err
			}
			if _, err = rd.Seek(pos+int64(alen), io.SeekStart); err != nil {
				return err
			}
		case 0x81: /* StringArray */
			if alen < 2 {
				break
			}
			buf := make([]uint16, alen/2)
			if err = readWordN(rd, buf); err != nil {
				return err
			}
			start := 0
			v = "["
			for i := 0; i < len(buf); i++ {
				if buf[i] == 0 {
					/* end of string */
					s, err := convertUnicodeString(buf[start:i])
					if err != nil {
						return err
					}
					v += "'" + s + "',"
					start = i + 1
				}
			}
			v += "]"

		default:
			buf := make([]byte, alen)
			if _, err = io.ReadFull(rd, buf); err != nil {
				return err
			}
			for _, b := range buf {
				fmt.Printf("%02x", b)
			}
			return fmt.Errorf("Unknown arg type 0x%X\n", atype)
		}

		aname, ok := t.subst[i]
		if !ok && atype != 0x00 /* void */ {
			aname = fmt.Sprintf("arg_%d", i)
		}
		p.variable[aname] = v
		// fmt.Printf(" arg %v: %v\n", i, v)
	}
	return nil
}

func (p *parser) parseBinXML(rd io.ReadSeeker) error {
	var err error

	// fmt.Printf("============= binXML ==================\n")
out:
	for err == nil {
		var t [1]byte
		if _, err = io.ReadFull(rd, t[:]); err != nil {
			break
		}
		tag := t[0]
		//fmt.Printf("Tag: %X\n", tag)
		switch tag {
		case 0x00: // EOF
			break out
		case 0x01: // OpenStartElementToken
			err = p.OpenStartElement(rd, false)
		case 0x41: // OpenStartElementToken w/attr
			err = p.OpenStartElement(rd, true)
		case 0x02: // CloseStartElementToken
			err = p.CloseStartElement(rd)
		case 0x03, 0x04: /*  CloseEmptyElementToken, CloseElementToken  */
			err = p.CloseElement(rd)
		case 0x05, 0x45: /*  ValueTextToken */
			err = p.ValueTextToken(rd)
		case 0x06, 0x46: /*  AttributeToken */
			err = p.AttributeToken(rd)
		//case 0x07:	/* CDATASectionToken */
		//case 0x47:
		//case 0x08:	/* CharRefToken */
		//case 0x48:
		//case 0x09:	/*  EntityRefToken */
		//case 0x49:
		//case 0x0A:	/*  PITargetToken */
		//case 0x0B:	/*  PIDataToken */
		case 0x0C: /*  TemplateInstanceToken */
			err = p.TemplateInstance(rd)
		case 0x0D, 0x0E: /*  NormalSubstitutionToken, OptionalSubstitutionToken  */
			err = p.SubstitutionToken(rd)
		case 0x0F: /*  FragmentHeaderToken */
			rd.Seek(3, io.SeekCurrent)
			break

		default:
			err = fmt.Errorf("Unknown tag %q", tag)
		}
	}

	return err
}

func readRecordHeader(rd io.ReadSeeker, rh *recHeader) error {
	var err error
	if rh.Magic, err = readDword(rd); err != nil {
		return err
	}
	if rh.Sz, err = readDword(rd); err != nil {
		return err
	}
	if rh.Num, err = readQword(rd); err != nil {
		return err
	}
	if rh.Timestamp, err = readQword(rd); err != nil {
		return err
	}
	return nil
}

// Completely parse the EVTX file, use hnd as callback for every record found
func ParseEvtx(fname string, hnd EventHandler) error {
	f, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer f.Close()

	magicValue := [8]byte{'E', 'l', 'f', 'F', 'i', 'l', 'e', 0x00}
	chunkMagic := [8]byte{'E', 'l', 'f', 'C', 'h', 'n', 'k', 0x00}

	var header evtxHeader
	var ch chunkHeader
	var rh recHeader

	err = binary.Read(f, binary.LittleEndian, &header)
	if err != nil {
		return err
	}
	if header.Magic != magicValue {
		return fmt.Errorf("Header's magic: got %v, expect %v", header.Magic, magicValue)
	}
	if v := uint32(0x00030001); header.Version != v {
		return fmt.Errorf("Header's version: got %v, expect %v", header.Version, v)
	}

	chunk := make([]byte, 0x10000, 0x10000)
	rd := bytes.NewReader(chunk)

	p := newParser()

	for {
		p.Reset()

		// fmt.Printf("==== CHUNK ====\n")
		// fpos, _ := f.Seek(0, io.SeekCurrent)
		nread, err := io.ReadFull(f, chunk)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read chunk: %v", err)
		}
		if nread != len(chunk) {
			pos, _ := f.Seek(0, io.SeekCurrent)
			return fmt.Errorf("failed to read chunk at 0x%X", pos)
		}
		rd.Seek(0, io.SeekStart)
		err = binary.Read(rd, binary.LittleEndian, &ch)
		if err != nil {
			return fmt.Errorf("read chunk header: %v", err)
		}

		if ch.Magic != chunkMagic {
			if ch.Magic == [8]byte{} {
				// empty chunk
				continue
			}
			pos, _ := f.Seek(0, io.SeekCurrent)
			return fmt.Errorf("chunk magic: got %v, expect %v at 0x%X", ch.Magic, chunkMagic, pos)
		}

		for {
			pos, _ := rd.Seek(0, io.SeekCurrent)
			err = readRecordHeader(rd, &rh)
			if err != nil {
				break
			}
			var magic uint32 = 0x00002A2A
			if rh.Magic != magic {
				// leftovers from old records, etc till the end of chunk
				break
			}
			if rh.Sz < recHeaderSize {
				return fmt.Errorf("rec size less than its header size")
			}

			if int(pos+int64(rh.Sz)) > len(chunk) {
				return fmt.Errorf("rec size out of chunk")
			}

			p.ResetPerRecord()
			err = p.parseBinXML(rd)
			if err != nil {
				return err
			}

			t := timeFromFileTime(rh.Timestamp)

			hnd(t, rh.Num, p.variable)
			rd.Seek(pos+int64(rh.Sz), io.SeekStart)
		}
	}

	return nil
}

