// OGPSSpoofChk — GPS Spoofing Detector
// OWL Security Tools · Batch 3 (Wireless)
// Author : khaled.s.haddad    Website : owlsec.org
// Language: Go (stdlib only, CGO disabled, static). Authorized testing use only.
//
// This tool performs OFFLINE analysis of wireless protocol artifacts (pcap, hex,
// CSV, IQ, NMEA, LDIF-style captures). It never touches a live radio. All parsing,
// frame dissection, scoring and reporting runs purely on supplied files.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/bits"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const APPNAME = "OGPSSpoofChk"
const SUITE = "Owl Wireless Suite"
const TAGLINE = "GPS / GNSS Spoofing Detector"
const SUBLINE = "NMEA · position jumps · time/altitude sanity · SNR uniformity · pcap · offline"
const CATEGORY = "OWireless"
const VERSION = "1.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"

const BANNER = `
 ██████╗  ██████╗ ██████╗ ███████╗███████╗██████╗  ██████╗  ██████╗ ███████╗ ██████╗██╗  ██╗██╗  ██╗
██╔═══██╗██╔════╝ ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██║  ██║██║ ██╔╝
██║   ██║██║  ███╗██████╔╝███████╗███████╗██████╔╝██║   ██║██║   ██║█████╗  ██║     ███████║█████╔╝ 
██║   ██║██║   ██║██╔═══╝ ╚════██║╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██║     ██╔══██║██╔═██╗ 
╚██████╔╝╚██████╔╝██║     ███████║███████║██║     ╚██████╔╝╚██████╔╝██║     ╚██████╗██║  ██║██║  ██╗
 ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
`

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and CRITICAL/HIGH.
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
	DR  = CY // legacy alias (was dark-red frame) → cyan
	CYN = CY // legacy alias
	MAG = MG // legacy alias
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if noColor {
		fmt.Println()
		return
	}
	fmt.Print("\033[H\033[2J")
}
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), DR)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0) // stdin closed (Ctrl-D / end of piped input)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}
func menu(title string, items []menuEntry) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " +
			col(pad(it.Label, 26), W) + col("─ "+it.Desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 26), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col(pad("Exit", 26), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	rule()
	return prompt("Select option")
}
func pad(s string, n int) string {
	if vlen(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-vlen(s))
}
func vlen(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = vlen(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && vlen(c) > w[i] {
				w[i] = vlen(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DR))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DR))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DR))
			}
		}
		fmt.Println("  " + rb.String())
	}
}
func sectionHead(s string) {
	fmt.Println()
	rule()
	fmt.Println("  " + col("⬡  "+s, B+CY))
	rule()
}

// ============================ DATA MODEL ============================

// Severity levels, ordered.
const (
	SevInfo = "INFO"
	SevLow  = "LOW"
	SevMed  = "MEDIUM"
	SevHigh = "HIGH"
	SevCrit = "CRITICAL"
)

// Finding is a single analysis result with MITRE ATT&CK mapping.
type Finding struct {
	ID    string   `json:"id"`
	Title string   `json:"title"`
	Sev   string   `json:"severity"`
	Desc  string   `json:"description"`
	Loc   string   `json:"location"`
	Mitre []string `json:"mitre"`
	Rec   string   `json:"recommendation"`
	Score int      `json:"score"`
}

// Table is a named grid of rows for structured output.
type Table struct {
	Title   string     `json:"title"`
	Headers []string   `json:"headers"`
	Rows    [][]string `json:"rows"`
}

// KV is an ordered key/value pair for summary stats.
type KV struct {
	K string `json:"key"`
	V string `json:"value"`
}

// Report is the unified analysis output every tool produces.
type Report struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	Category  string    `json:"category"`
	Generated string    `json:"generated"`
	Source    string    `json:"source"`
	Grade     string    `json:"grade"`
	Score     int       `json:"score"`
	Stats     []KV      `json:"stats"`
	Tables    []Table   `json:"tables"`
	Findings  []Finding `json:"findings"`
	Notes     []string  `json:"notes"`
}

func sevRank(s string) int {
	switch s {
	case SevCrit:
		return 4
	case SevHigh:
		return 3
	case SevMed:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}
func sevColor(s string) string {
	switch s {
	case SevCrit:
		return MAG + B
	case SevHigh:
		return R + B
	case SevMed:
		return YLW
	case SevLow:
		return CYN
	default:
		return GY
	}
}

// addFinding appends a finding with a stable auto id when none given.
func (r *Report) add(f Finding) {
	if f.ID == "" {
		f.ID = fmt.Sprintf("%s-%03d", shortTool(), len(r.Findings)+1)
	}
	if f.Score == 0 {
		f.Score = sevRank(f.Sev) * 20
	}
	r.Findings = append(r.Findings, f)
}
func (r *Report) stat(k, v string) { r.Stats = append(r.Stats, KV{k, v}) }
func (r *Report) note(s string)    { r.Notes = append(r.Notes, s) }
func (r *Report) addTable(t Table) { r.Tables = append(r.Tables, t) }

func shortTool() string {
	s := APPNAME
	if len(s) <= 6 {
		return strings.ToUpper(s)
	}
	return strings.ToUpper(s[:6])
}

// grade computes an A+..F posture grade from the finding mix.
func (r *Report) grade() {
	total := 0
	worst := 0
	for _, f := range r.Findings {
		total += sevRank(f.Sev)
		if sevRank(f.Sev) > worst {
			worst = sevRank(f.Sev)
		}
	}
	// Penalty model: weighted by severity density and worst-case.
	pen := total*6 + worst*12
	score := 100 - pen
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	r.Score = score
	r.Grade = gradeLetter(score)
}
func gradeLetter(score int) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 87:
		return "B+"
	case score >= 83:
		return "B"
	case score >= 80:
		return "B-"
	case score >= 77:
		return "C+"
	case score >= 73:
		return "C"
	case score >= 70:
		return "C-"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func newReport(src string) *Report {
	return &Report{
		Tool:      APPNAME,
		Version:   VERSION,
		Category:  CATEGORY,
		Generated: time.Now().Format("2006-01-02 15:04:05 -0700"),
		Source:    src,
	}
}

// ============================ BYTE / BIT UTILITIES ============================

// bitReader reads MSB-first bits from a byte slice.
type bitReader struct {
	data []byte
	pos  int // bit position
}

func newBitReader(b []byte) *bitReader { return &bitReader{data: b} }
func (br *bitReader) remaining() int   { return len(br.data)*8 - br.pos }
func (br *bitReader) bit() int {
	if br.pos >= len(br.data)*8 {
		return 0
	}
	byteIdx := br.pos / 8
	bitIdx := 7 - uint(br.pos%8)
	br.pos++
	return int((br.data[byteIdx] >> bitIdx) & 1)
}
func (br *bitReader) bits(n int) uint64 {
	var v uint64
	for i := 0; i < n; i++ {
		v = (v << 1) | uint64(br.bit())
	}
	return v
}
func (br *bitReader) align() {
	if br.pos%8 != 0 {
		br.pos += 8 - (br.pos % 8)
	}
}

// leReader / beReader provide bounds-checked integer reads.
type byteCursor struct {
	b   []byte
	off int
	err error
}

func newCursor(b []byte) *byteCursor { return &byteCursor{b: b} }
func (c *byteCursor) rem() int       { return len(c.b) - c.off }
func (c *byteCursor) u8() uint8 {
	if c.off+1 > len(c.b) {
		c.err = errors.New("eof u8")
		return 0
	}
	v := c.b[c.off]
	c.off++
	return v
}
func (c *byteCursor) u16le() uint16 {
	if c.off+2 > len(c.b) {
		c.err = errors.New("eof u16")
		return 0
	}
	v := binary.LittleEndian.Uint16(c.b[c.off:])
	c.off += 2
	return v
}
func (c *byteCursor) u16be() uint16 {
	if c.off+2 > len(c.b) {
		c.err = errors.New("eof u16be")
		return 0
	}
	v := binary.BigEndian.Uint16(c.b[c.off:])
	c.off += 2
	return v
}
func (c *byteCursor) u32le() uint32 {
	if c.off+4 > len(c.b) {
		c.err = errors.New("eof u32")
		return 0
	}
	v := binary.LittleEndian.Uint32(c.b[c.off:])
	c.off += 4
	return v
}
func (c *byteCursor) u32be() uint32 {
	if c.off+4 > len(c.b) {
		c.err = errors.New("eof u32be")
		return 0
	}
	v := binary.BigEndian.Uint32(c.b[c.off:])
	c.off += 4
	return v
}
func (c *byteCursor) u64le() uint64 {
	if c.off+8 > len(c.b) {
		c.err = errors.New("eof u64")
		return 0
	}
	v := binary.LittleEndian.Uint64(c.b[c.off:])
	c.off += 8
	return v
}
func (c *byteCursor) take(n int) []byte {
	if c.off+n > len(c.b) || n < 0 {
		c.err = errors.New("eof take")
		return nil
	}
	v := c.b[c.off : c.off+n]
	c.off += n
	return v
}

func popcount(v uint64) int { return bits.OnesCount64(v) }

// shannonEntropy returns bits/byte (0..8).
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, x := range b {
		freq[x]++
	}
	var e float64
	n := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		e -= p * math.Log2(p)
	}
	return e
}

// hexDump renders a classic hex+ascii dump.
func hexDump(data []byte, base int) string {
	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		sb.WriteString(fmt.Sprintf("  %08x  ", base+i))
		for j := i; j < i+16; j++ {
			if j < end {
				sb.WriteString(fmt.Sprintf("%02x ", data[j]))
			} else {
				sb.WriteString("   ")
			}
			if j == i+7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" |")
		for j := i; j < end; j++ {
			c := data[j]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

func macStr(b []byte) string {
	if len(b) < 6 {
		return "??:??:??:??:??:??"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}
func revMac(b []byte) string {
	if len(b) < 6 {
		return "??"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[5], b[4], b[3], b[2], b[1], b[0])
}

// isLocallyAdministered reports the U/L bit on a MAC (randomized-MAC hint).
func isLocallyAdministered(b []byte) bool {
	if len(b) < 1 {
		return false
	}
	return b[0]&0x02 != 0
}
func isMulticast(b []byte) bool {
	if len(b) < 1 {
		return false
	}
	return b[0]&0x01 != 0
}

// ============================ CRYPTO HELPERS (stdlib) ============================

func md5hex(b []byte) string    { h := md5.Sum(b); return hex.EncodeToString(h[:]) }
func sha1hex(b []byte) string   { h := sha1.Sum(b); return hex.EncodeToString(h[:]) }
func sha256hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func hmacSHA1(key, msg []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// pbkdf2SHA1 is a stdlib implementation (used for WPA PMK derivation, etc.).
func pbkdf2SHA1(password, salt []byte, iter, keyLen int) []byte {
	hLen := sha1.Size
	numBlocks := (keyLen + hLen - 1) / hLen
	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		var blk [4]byte
		binary.BigEndian.PutUint32(blk[:], uint32(block))
		u := hmacSHA1(password, append(append([]byte{}, salt...), blk[:]...))
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			u = hmacSHA1(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// aesCMAC implements RFC 4493 (used for LoRaWAN MIC, etc.).
func aesCMAC(key, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	bs := block.BlockSize()
	zero := make([]byte, bs)
	l := make([]byte, bs)
	block.Encrypt(l, zero)
	k1 := leftShiftXor(l)
	k2 := leftShiftXor(k1)

	var lastBlock []byte
	n := (len(msg) + bs - 1) / bs
	complete := false
	if n == 0 {
		n = 1
	} else {
		complete = len(msg)%bs == 0
	}
	if complete {
		lastBlock = xorBytes(msg[(n-1)*bs:], k1)
	} else {
		rem := msg[(n-1)*bs:]
		padded := make([]byte, bs)
		copy(padded, rem)
		padded[len(rem)] = 0x80
		lastBlock = xorBytes(padded, k2)
	}
	x := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		y := xorBytes(x, msg[i*bs:(i+1)*bs])
		block.Encrypt(x, y)
	}
	y := xorBytes(x, lastBlock)
	out := make([]byte, bs)
	block.Encrypt(out, y)
	return out
}
func leftShiftXor(b []byte) []byte {
	out := make([]byte, len(b))
	carry := byte(0)
	for i := len(b) - 1; i >= 0; i-- {
		out[i] = (b[i] << 1) | carry
		carry = (b[i] >> 7) & 1
	}
	if b[0]&0x80 != 0 {
		out[len(out)-1] ^= 0x87
	}
	return out
}
func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// aesCTRDecrypt used for lab decryption helpers.
func aesCTRDecrypt(key, iv, ct []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, len(ct))
	s := cipher.NewCTR(block, iv)
	s.XORKeyStream(out, ct)
	return out
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func b64decode(s string) []byte {
	d, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	return d
}

// crc8 (poly 0x07) used by a few sensor/radio frame formats.
func crc8(b []byte) byte {
	var crc byte
	for _, x := range b {
		crc ^= x
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// crc16CCITT (poly 0x1021) used by Z-Wave and others.
func crc16CCITT(b []byte) uint16 {
	crc := uint16(0x1D0F)
	for _, x := range b {
		crc ^= uint16(x) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// crc32IEEE (reflected, poly 0xEDB88320) — 802.11 FCS style.
func crc32IEEE(b []byte) uint32 {
	crc := ^uint32(0)
	for _, x := range b {
		crc ^= uint32(x)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

// ============================ INPUT LOADERS ============================

// CapFrame is one captured frame with metadata.
type CapFrame struct {
	Index    int
	TsSec    uint32
	TsUsec   uint32
	Data     []byte
	OrigLen  uint32
	LinkType uint32
}

const (
	LinkEthernet   = 1
	LinkRaw        = 101
	Link80211      = 105
	Link80211Radio = 127 // radiotap
	LinkPPI        = 192
	LinkBLE        = 251
	Link802154     = 195
)

// loadBytes reads a file (or returns error).
func loadBytes(path string) ([]byte, error) {
	return os.ReadFile(strings.TrimSpace(path))
}

// looksHex reports whether a blob is a hex/whitespace text dump.
func looksHex(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	n := 0
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		case c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ':' || c == ',':
		case c == 'x' || c == 'X':
		default:
			return false
		}
		n++
		if n > 4096 {
			break
		}
	}
	return true
}

// parseHexDump converts a hex text blob into raw bytes.
func parseHexDump(b []byte) []byte {
	s := string(b)
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, "0X", "")
	var sb strings.Builder
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			sb.WriteRune(c)
		}
	}
	h := sb.String()
	if len(h)%2 == 1 {
		h = h[:len(h)-1]
	}
	out, _ := hex.DecodeString(h)
	return out
}

// parsePcap parses classic libpcap files (both endiannesses).
func parsePcap(b []byte) ([]CapFrame, uint32, error) {
	if len(b) < 24 {
		return nil, 0, errors.New("pcap: too short")
	}
	magic := binary.BigEndian.Uint32(b[0:4])
	var bo binary.ByteOrder
	switch magic {
	case 0xa1b2c3d4, 0xa1b2cd34:
		bo = binary.BigEndian
	case 0xd4c3b2a1, 0x34cdb2a1:
		bo = binary.LittleEndian
	default:
		return nil, 0, errors.New("pcap: bad magic")
	}
	linkType := bo.Uint32(b[20:24])
	var frames []CapFrame
	off := 24
	idx := 0
	for off+16 <= len(b) {
		tsSec := bo.Uint32(b[off : off+4])
		tsUsec := bo.Uint32(b[off+4 : off+8])
		inclLen := bo.Uint32(b[off+8 : off+12])
		origLen := bo.Uint32(b[off+12 : off+16])
		off += 16
		if off+int(inclLen) > len(b) || inclLen > 1<<24 {
			break
		}
		data := make([]byte, inclLen)
		copy(data, b[off:off+int(inclLen)])
		off += int(inclLen)
		frames = append(frames, CapFrame{Index: idx, TsSec: tsSec, TsUsec: tsUsec, Data: data, OrigLen: origLen, LinkType: linkType})
		idx++
	}
	return frames, linkType, nil
}

// parsePcapNG parses a minimal subset of the pcapng format (SHB/IDB/EPB/SPB).
func parsePcapNG(b []byte) ([]CapFrame, uint32, error) {
	if len(b) < 12 || binary.LittleEndian.Uint32(b[0:4]) != 0x0A0D0D0A {
		return nil, 0, errors.New("pcapng: not a section header")
	}
	bo := binary.ByteOrder(binary.LittleEndian)
	if binary.LittleEndian.Uint32(b[8:12]) != 0x1A2B3C4D {
		if binary.BigEndian.Uint32(b[8:12]) == 0x1A2B3C4D {
			bo = binary.BigEndian
		}
	}
	var frames []CapFrame
	var linkType uint32
	off := 0
	idx := 0
	for off+12 <= len(b) {
		bt := bo.Uint32(b[off : off+4])
		blen := bo.Uint32(b[off+4 : off+8])
		if blen < 12 || off+int(blen) > len(b) {
			break
		}
		body := b[off+8 : off+int(blen)-4]
		switch bt {
		case 0x00000001: // IDB
			if len(body) >= 2 {
				linkType = uint32(bo.Uint16(body[0:2]))
			}
		case 0x00000006: // EPB
			if len(body) >= 20 {
				capLen := bo.Uint32(body[12:16])
				if 20+int(capLen) <= len(body) {
					d := make([]byte, capLen)
					copy(d, body[20:20+int(capLen)])
					frames = append(frames, CapFrame{Index: idx, Data: d, OrigLen: capLen, LinkType: linkType})
					idx++
				}
			}
		case 0x00000003: // SPB
			if len(body) >= 4 {
				d := make([]byte, len(body)-4)
				copy(d, body[4:])
				frames = append(frames, CapFrame{Index: idx, Data: d, OrigLen: uint32(len(d)), LinkType: linkType})
				idx++
			}
		}
		off += int(blen)
	}
	return frames, linkType, nil
}

// loadCapture resolves pcap/pcapng/hex automatically.
func loadCapture(path string) ([]CapFrame, uint32, error) {
	b, err := loadBytes(path)
	if err != nil {
		return nil, 0, err
	}
	return decodeCapture(b)
}
func decodeCapture(b []byte) ([]CapFrame, uint32, error) {
	if len(b) >= 4 {
		m := binary.BigEndian.Uint32(b[0:4])
		if m == 0xa1b2c3d4 || m == 0xd4c3b2a1 || m == 0xa1b2cd34 || m == 0x34cdb2a1 {
			return parsePcap(b)
		}
		if binary.LittleEndian.Uint32(b[0:4]) == 0x0A0D0D0A {
			return parsePcapNG(b)
		}
	}
	if looksHex(b) {
		raw := parseHexDump(b)
		if len(raw) > 0 {
			return []CapFrame{{Index: 0, Data: raw, OrigLen: uint32(len(raw)), LinkType: Link80211}}, Link80211, nil
		}
	}
	return []CapFrame{{Index: 0, Data: b, OrigLen: uint32(len(b)), LinkType: LinkRaw}}, LinkRaw, nil
}

// stripRadiotap removes a radiotap header if present, returning the 802.11 body.
func stripRadiotap(f CapFrame) []byte {
	if f.LinkType != Link80211Radio {
		return f.Data
	}
	if len(f.Data) < 4 {
		return f.Data
	}
	l := int(binary.LittleEndian.Uint16(f.Data[2:4]))
	if l <= 0 || l > len(f.Data) {
		return f.Data
	}
	return f.Data[l:]
}

// ============================ EXPORT ENGINE ============================

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Sev) != sevRank(fs[j].Sev) {
			return sevRank(fs[i].Sev) > sevRank(fs[j].Sev)
		}
		return fs[i].ID < fs[j].ID
	})
}

func render(r *Report, format string) string {
	sortFindings(r.Findings)
	switch strings.ToLower(format) {
	case "md", "markdown":
		return exportMD(r)
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

func exportTXT(r *Report) string {
	var sb strings.Builder
	w := func(f string, a ...interface{}) { sb.WriteString(fmt.Sprintf(f, a...)) }
	w("%s\n", strings.Repeat("=", 72))
	w("%s  v%s  [%s]\n", r.Tool, r.Version, r.Category)
	w("%s\n", TAGLINE)
	w("Generated : %s\n", r.Generated)
	w("Source    : %s\n", r.Source)
	w("Grade     : %s  (score %d/100)\n", r.Grade, r.Score)
	w("%s\n", strings.Repeat("=", 72))
	if len(r.Stats) > 0 {
		w("\n-- SUMMARY --\n")
		for _, s := range r.Stats {
			w("  %-28s : %s\n", s.K, s.V)
		}
	}
	for _, t := range r.Tables {
		w("\n-- %s --\n", t.Title)
		w("%s\n", strings.Join(t.Headers, " | "))
		for _, row := range t.Rows {
			w("%s\n", strings.Join(row, " | "))
		}
	}
	if len(r.Findings) > 0 {
		w("\n-- FINDINGS (%d) --\n", len(r.Findings))
		for _, f := range r.Findings {
			w("\n[%s] %s  (%s)\n", f.Sev, f.Title, f.ID)
			if f.Loc != "" {
				w("  location : %s\n", f.Loc)
			}
			w("  detail   : %s\n", f.Desc)
			if len(f.Mitre) > 0 {
				w("  mitre    : %s\n", strings.Join(f.Mitre, ", "))
			}
			if f.Rec != "" {
				w("  fix      : %s\n", f.Rec)
			}
		}
	}
	if len(r.Notes) > 0 {
		w("\n-- NOTES --\n")
		for _, n := range r.Notes {
			w("  * %s\n", n)
		}
	}
	w("\n%s\n", strings.Repeat("=", 72))
	w("Authorized testing only. (c) owlsec.org — khaled.s.haddad\n")
	return sb.String()
}

func exportMD(r *Report) string {
	var sb strings.Builder
	w := func(f string, a ...interface{}) { sb.WriteString(fmt.Sprintf(f, a...)) }
	w("# %s report\n\n", r.Tool)
	w("> %s\n\n", TAGLINE)
	w("| Field | Value |\n|---|---|\n")
	w("| Tool | %s v%s |\n", r.Tool, r.Version)
	w("| Category | %s |\n", r.Category)
	w("| Generated | %s |\n", r.Generated)
	w("| Source | %s |\n", mdEsc(r.Source))
	w("| Grade | **%s** (%d/100) |\n", r.Grade, r.Score)
	if len(r.Stats) > 0 {
		w("\n## Summary\n\n| Metric | Value |\n|---|---|\n")
		for _, s := range r.Stats {
			w("| %s | %s |\n", mdEsc(s.K), mdEsc(s.V))
		}
	}
	for _, t := range r.Tables {
		w("\n## %s\n\n", t.Title)
		w("| %s |\n", strings.Join(t.Headers, " | "))
		w("|%s\n", strings.Repeat("---|", len(t.Headers)))
		for _, row := range t.Rows {
			esc := make([]string, len(row))
			for i, c := range row {
				esc[i] = mdEsc(c)
			}
			w("| %s |\n", strings.Join(esc, " | "))
		}
	}
	if len(r.Findings) > 0 {
		w("\n## Findings\n\n")
		for _, f := range r.Findings {
			w("### [%s] %s `%s`\n\n", f.Sev, f.Title, f.ID)
			if f.Loc != "" {
				w("- **Location**: %s\n", mdEsc(f.Loc))
			}
			w("- **Detail**: %s\n", mdEsc(f.Desc))
			if len(f.Mitre) > 0 {
				w("- **MITRE**: %s\n", strings.Join(f.Mitre, ", "))
			}
			if f.Rec != "" {
				w("- **Fix**: %s\n", mdEsc(f.Rec))
			}
			w("\n")
		}
	}
	if len(r.Notes) > 0 {
		w("\n## Notes\n\n")
		for _, n := range r.Notes {
			w("- %s\n", mdEsc(n))
		}
	}
	return sb.String()
}
func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func exportJSON(r *Report) string {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

func exportCSV(r *Report) string {
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	cw.Write([]string{"type", "id", "severity", "title", "location", "mitre", "detail", "recommendation"})
	for _, f := range r.Findings {
		cw.Write([]string{"finding", f.ID, f.Sev, f.Title, f.Loc, strings.Join(f.Mitre, ";"), f.Desc, f.Rec})
	}
	for _, t := range r.Tables {
		for _, row := range t.Rows {
			rec := []string{"row:" + t.Title}
			rec = append(rec, row...)
			cw.Write(rec)
		}
	}
	cw.Flush()
	return buf.String()
}

// exportSARIF produces SARIF 2.1.0 with findings as results.
func exportSARIF(r *Report) string {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string                 `json:"id"`
		Name             string                 `json:"name"`
		ShortDescription sarifMsg               `json:"shortDescription"`
		FullDescription  sarifMsg               `json:"fullDescription"`
		Properties       map[string]interface{} `json:"properties,omitempty"`
		HelpURI          string                 `json:"helpUri,omitempty"`
	}
	type sarifLoc struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID     string                 `json:"ruleId"`
		Level      string                 `json:"level"`
		Message    sarifMsg               `json:"message"`
		Locations  []sarifLoc             `json:"locations,omitempty"`
		Properties map[string]interface{} `json:"properties,omitempty"`
	}
	level := func(s string) string {
		switch s {
		case SevCrit, SevHigh:
			return "error"
		case SevMed:
			return "warning"
		case SevLow:
			return "note"
		default:
			return "none"
		}
	}
	ruleSet := map[string]sarifRule{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range r.Findings {
		if _, ok := ruleSet[f.ID]; !ok {
			rule := sarifRule{
				ID:               f.ID,
				Name:             strings.ReplaceAll(f.Title, " ", ""),
				ShortDescription: sarifMsg{Text: f.Title},
				FullDescription:  sarifMsg{Text: f.Desc},
				HelpURI:          "https://owlsec.org",
				Properties:       map[string]interface{}{"mitre": f.Mitre, "severity": f.Sev},
			}
			ruleSet[f.ID] = rule
			rules = append(rules, rule)
		}
		res := sarifResult{
			RuleID:     f.ID,
			Level:      level(f.Sev),
			Message:    sarifMsg{Text: f.Desc},
			Properties: map[string]interface{}{"mitre": f.Mitre, "recommendation": f.Rec},
		}
		if f.Loc != "" {
			var l sarifLoc
			l.PhysicalLocation.ArtifactLocation.URI = f.Loc
			res.Locations = append(res.Locations, l)
		}
		results = append(results, res)
	}
	doc := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           r.Tool,
						"version":        r.Version,
						"informationUri": "https://owlsec.org",
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ============================ HOW TO USE SCREEN ============================
//
// Domain code must define these package-level variables:
//   howtoWarning string      — the LEGAL & ETHICAL WARNING text
//   howtoSteps   []string    — numbered HOW TO USE steps
//   howtoNav     []string    — NAVIGATION key descriptions
//   howtoReq     []string    — REQUIREMENTS list
//   howtoNotes   []string    — feature / protocol notes
// and a func analyze(src string, demo bool) *Report.

func showHowto() {
	clear()
	banner()
	fmt.Println()
	fmt.Println("  " + col("╔══════════════════════════════════════════════════════════════╗", DR))
	fmt.Println("  " + col("║  ", DR) + col("HOW TO USE — "+APPNAME, CY+B) + col(strings.Repeat(" ", max(0, 48-len(APPNAME)))+"║", DR))
	fmt.Println("  " + col("╚══════════════════════════════════════════════════════════════╝", DR))

	sectionHead("LEGAL & ETHICAL WARNING")
	for _, l := range wrapText(howtoWarning, 66) {
		fmt.Println("  " + col(l, YLW))
	}

	sectionHead("HOW TO USE")
	for i, s := range howtoSteps {
		fmt.Printf("   %s %s\n", col(fmt.Sprintf("%2d.", i+1), CY+B), col(s, W))
	}

	sectionHead("REQUIREMENTS")
	for _, s := range howtoReq {
		fmt.Println("   " + col("- ", DR) + col(s, GY))
	}

	sectionHead("FEATURE / PROTOCOL NOTES")
	for _, s := range howtoNotes {
		for _, l := range wrapText(s, 64) {
			fmt.Println("   " + col(l, W))
		}
	}
	fmt.Println()
	line(64)
	fmt.Println("  " + col("MITRE ATT&CK : ", DIM) + col(MITREID, R))
	fmt.Println("  " + col("Export formats: txt · md · json · csv · sarif", GY))
}

// printHowto renders the same content for the --howto CLI flag (no screen clear).
func printHowto() {
	savedNo := noColor
	_ = savedNo
	fmt.Println(APPNAME + " — HOW TO USE")
	fmt.Println(strings.Repeat("=", 64))
	fmt.Println("\n[LEGAL & ETHICAL WARNING]")
	for _, l := range wrapText(howtoWarning, 70) {
		fmt.Println("  " + l)
	}
	fmt.Println("\n[HOW TO USE]")
	for i, s := range howtoSteps {
		fmt.Printf("  %2d. %s\n", i+1, s)
	}
	fmt.Println("\n[REQUIREMENTS]")
	for _, s := range howtoReq {
		fmt.Println("  - " + s)
	}
	fmt.Println("\n[FEATURE / PROTOCOL NOTES]")
	for _, s := range howtoNotes {
		for _, l := range wrapText(s, 70) {
			fmt.Println("  " + l)
		}
	}
	fmt.Println("\nMITRE ATT&CK: " + MITREID)
	fmt.Println("Export formats: txt md json csv sarif")
}

func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	var cur string
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	if len(lines) == 0 {
		lines = []string{""}
	}
	return lines
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ============================ GENERIC HANDLERS ============================

func showReport(r *Report) {
	sortFindings(r.Findings)
	for _, s := range r.Stats {
		info(s.K + " : " + s.V)
	}
	for _, t := range r.Tables {
		if len(t.Rows) == 0 {
			continue
		}
		sectionHead(t.Title)
		shown := t.Rows
		if len(shown) > 40 {
			shown = shown[:40]
		}
		table(t.Headers, shown)
		if len(t.Rows) > 40 {
			info(fmt.Sprintf("... %d more rows (use --output for full export)", len(t.Rows)-40))
		}
	}
	if len(r.Findings) > 0 {
		sectionHead(fmt.Sprintf("FINDINGS (%d)", len(r.Findings)))
		for _, f := range r.Findings {
			fmt.Printf("   %s %s %s\n", col("["+f.Sev+"]", sevColor(f.Sev)), col(f.Title, W), col("("+f.ID+")", GY))
			fmt.Println("      " + col(f.Desc, GY))
			if len(f.Mitre) > 0 {
				fmt.Println("      " + col("MITRE: "+strings.Join(f.Mitre, ", "), DIM))
			}
		}
	}
	sectionHead("POSTURE GRADE")
	gc := GRN + B
	if r.Score < 70 {
		gc = YLW
	}
	if r.Score < 60 {
		gc = R + B
	}
	fmt.Println("   " + col(r.Grade, gc) + col(fmt.Sprintf("   (%d/100)", r.Score), GY))
}

func handleRunFile() {
	p := prompt("capture / input file path")
	if p == "" {
		warnMsg("no path given")
		return
	}
	r := analyze(p, false)
	lastReport = r
	showReport(r)
}
func handleRunDemo() {
	info("running self-contained synthetic demo...")
	r := analyze("", true)
	lastReport = r
	showReport(r)
}

// lastReport is the most recent analysis, reused by Export.
var lastReport *Report

func handleExport() {
	r := lastReport
	if r != nil {
		info("exporting the last analysis (" + r.Source + ")")
	} else if p := prompt("input file (blank = demo)"); p == "" {
		r = analyze("", true)
	} else {
		r = analyze(p, false)
	}
	f := prompt("format [txt/md/json/csv/sarif]")
	if f == "" {
		f = "txt"
	}
	out := prompt("output file (blank = screen)")
	data := render(r, f)
	if out == "" {
		fmt.Println(data)
	} else {
		if err := os.WriteFile(out, []byte(data), 0644); err != nil {
			errMsg("write failed: " + err.Error())
		} else {
			okMsg("wrote " + out + " (" + f + ")")
		}
	}
}
func handleHowto() { showHowto() }

// menuEntry binds a label to a handler for the interactive TUI.
type menuEntry struct {
	Label string
	Desc  string
	Fn    func()
}

func interactive() {
	for {
		ch := menu(TAGLINE, menuDef)
		switch ch {
		case "00", "0", "q", "quit", "exit":
			clear()
			banner()
			okMsg("Session closed. Stay ethical. — owlsec.org")
			return
		case "":
			continue
		case "h", "H", "help", "?":
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(ch)
		if err != nil || n < 1 || n > len(menuDef) {
			errMsg("invalid selection")
			pause()
			continue
		}
		clear()
		banner()
		menuDef[n-1].Fn()
		pause()
	}
}

// ============================ CLI / MAIN ============================

func usage() {
	banner()
	sec := func(t string) { fmt.Println("  " + col(t, CY+B)) }
	sec("USAGE")
	fmt.Println("    " + APPNAME + " [flags]            (no flags → interactive TUI)")
	fmt.Println()
	sec("DESCRIPTION")
	fmt.Println("    GNSS spoofing detector for NMEA 0183 logs: impossible speed / teleport, clock")
	fmt.Println("    rollback, altitude jumps, uniform C/N0, perfect geometry, checksum failures.")
	fmt.Println("    Offline only — it reads logs, it never transmits.")
	fmt.Println()
	sec("INPUT")
	fmt.Println("    --input FILE     NMEA text log, or pcap / pcapng carrying NMEA over UDP/TCP")
	fmt.Println("    --pcap FILE      alias for --input")
	fmt.Println("    --path FILE      alias for --input")
	fmt.Println("    --target STR     label recorded in the report (e.g. receiver or vessel name)")
	fmt.Println()
	sec("REPORTING")
	fmt.Println("    --format FMT     txt | md | json | csv | sarif (default txt)")
	fmt.Println("    --output FILE    write report to FILE instead of stdout")
	fmt.Println("    --no-color       disable ANSI colors")
	fmt.Println()
	sec("GENERAL")
	fmt.Println("    --demo           run built-in synthetic spoof dataset")
	fmt.Println("    --howto          print the HOW TO USE guide (legal, steps, protocol notes)")
	fmt.Println("    --selftest       run built-in self-tests (exit 0/1)")
	fmt.Println("    --version        print version and exit")
	fmt.Println("    -h, --help       show this help")
	fmt.Println()
	sec("EXAMPLES")
	fmt.Println("    gpspipe -r -n 2000 > track.nmea && " + APPNAME + " --input track.nmea")
	fmt.Println("    " + APPNAME + " --input drive.nmea --format json --output gnss.json")
	fmt.Println("    " + APPNAME + " --input gpsd-udp.pcapng --target \"bus-17\"")
	fmt.Println("    " + APPNAME + " --input track.nmea --format sarif --output gnss.sarif")
	fmt.Println("    " + APPNAME + " --demo --format md")
	fmt.Println()
	fmt.Println("  " + col("MITRE", CY+B) + "  " + MITREID)
	rule()
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func main() {
	flag.Usage = usage
	versionF := flag.Bool("version", false, "print version")
	howtoF := flag.Bool("howto", false, "print HOW TO USE guide")
	demoF := flag.Bool("demo", false, "run synthetic demo")
	formatF := flag.String("format", "txt", "output format")
	outputF := flag.String("output", "", "output file")
	inputF := flag.String("input", "", "input file")
	pcapF := flag.String("pcap", "", "capture file")
	targetF := flag.String("target", "", "target selector")
	pathF := flag.String("path", "", "input file alias")
	ncF := flag.Bool("no-color", false, "disable colors")
	selfF := flag.Bool("selftest", false, "run internal self-tests")
	flag.Parse()

	if *ncF {
		noColor = true
	}
	if *selfF {
		os.Exit(runSelfTest())
	}
	if *versionF {
		fmt.Printf("%s %s (owlsec.org / khaled.s.haddad)\n", APPNAME, VERSION)
		return
	}
	if *howtoF {
		printHowto()
		return
	}
	src := firstNonEmpty(*inputF, *pcapF, *pathF)
	if src == "" && !*demoF {
		interactive()
		return
	}
	var r *Report
	if *demoF {
		r = analyze("", true)
	} else {
		r = analyze(src, false)
	}
	if strings.TrimSpace(*targetF) != "" {
		r.note("target: " + *targetF)
	}
	out := render(r, *formatF)
	if *outputF != "" {
		if err := os.WriteFile(*outputF, []byte(out), 0644); err != nil {
			fmt.Fprintln(os.Stderr, "write error:", err)
			os.Exit(1)
		}
		fmt.Printf("%s: wrote %s report to %s\n", APPNAME, *formatF, *outputF)
		return
	}
	fmt.Print(out)
}

// ============================ SHARED ANALYSIS LIBRARY ============================
// Generic, protocol-agnostic helpers used across the wireless tool suite:
// descriptive statistics, light DSP, RF signal math, TLV walking, geo export
// and additional crypto primitives — all stdlib only.

// ---- descriptive statistics ----

func statMean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}
func statVariance(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := statMean(xs)
	s := 0.0
	for _, x := range xs {
		d := x - m
		s += d * d
	}
	return s / float64(len(xs)-1)
}
func statStdDev(xs []float64) float64 { return math.Sqrt(statVariance(xs)) }
func statMin(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}
func statMax(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}
func statMedian(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64{}, xs...)
	sort.Float64s(cp)
	n := len(cp)
	if n%2 == 1 {
		return cp[n/2]
	}
	return (cp[n/2-1] + cp[n/2]) / 2
}
func statPercentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64{}, xs...)
	sort.Float64s(cp)
	if p <= 0 {
		return cp[0]
	}
	if p >= 100 {
		return cp[len(cp)-1]
	}
	rank := (p / 100) * float64(len(cp)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return cp[lo]
	}
	frac := rank - float64(lo)
	return cp[lo]*(1-frac) + cp[hi]*frac
}
func statZScores(xs []float64) []float64 {
	m := statMean(xs)
	sd := statStdDev(xs)
	out := make([]float64, len(xs))
	if sd == 0 {
		return out
	}
	for i, x := range xs {
		out[i] = (x - m) / sd
	}
	return out
}
func movingAverage(xs []float64, win int) []float64 {
	if win < 1 {
		win = 1
	}
	out := make([]float64, len(xs))
	for i := range xs {
		lo := i - win + 1
		if lo < 0 {
			lo = 0
		}
		s := 0.0
		for j := lo; j <= i; j++ {
			s += xs[j]
		}
		out[i] = s / float64(i-lo+1)
	}
	return out
}

// histogram buckets a slice into n equal-width bins over [min,max].
func histogram(xs []float64, n int) ([]float64, []int) {
	if n < 1 {
		n = 1
	}
	lo, hi := statMin(xs), statMax(xs)
	edges := make([]float64, n+1)
	counts := make([]int, n)
	if hi == lo {
		hi = lo + 1
	}
	w := (hi - lo) / float64(n)
	for i := 0; i <= n; i++ {
		edges[i] = lo + float64(i)*w
	}
	for _, x := range xs {
		idx := int((x - lo) / w)
		if idx >= n {
			idx = n - 1
		}
		if idx < 0 {
			idx = 0
		}
		counts[idx]++
	}
	return edges, counts
}

// sparkline renders a compact unicode trend for a numeric series.
func sparkline(xs []float64) string {
	if len(xs) == 0 {
		return ""
	}
	blocks := []rune("▁▂▃▄▅▆▇█")
	lo, hi := statMin(xs), statMax(xs)
	rng := hi - lo
	if rng == 0 {
		rng = 1
	}
	var sb strings.Builder
	for _, x := range xs {
		idx := int(((x - lo) / rng) * float64(len(blocks)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}
		sb.WriteRune(blocks[idx])
	}
	return sb.String()
}

// ---- RF signal math ----

func dbmToMilliwatt(dbm float64) float64 { return math.Pow(10, dbm/10) }
func milliwattToDbm(mw float64) float64 {
	if mw <= 0 {
		return -200
	}
	return 10 * math.Log10(mw)
}

// rssiQuality maps dBm to a 0..100 link-quality estimate.
func rssiQuality(dbm float64) int {
	switch {
	case dbm >= -50:
		return 100
	case dbm <= -100:
		return 0
	default:
		return int(2 * (dbm + 100))
	}
}
func rssiBars(dbm float64) string {
	q := rssiQuality(dbm)
	n := q / 20
	if n > 5 {
		n = 5
	}
	return strings.Repeat("|", n) + strings.Repeat(".", 5-n)
}

// freqToChan maps a center frequency (MHz) to a Wi-Fi channel number.
func freqToChan(mhz int) int {
	switch {
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472:
		return (mhz-2412)/5 + 1
	case mhz >= 5160 && mhz <= 5885:
		return (mhz - 5000) / 5
	case mhz >= 5955 && mhz <= 7115: // 6 GHz
		return (mhz - 5950) / 5
	}
	return 0
}
func chanToFreq24(ch int) int {
	if ch == 14 {
		return 2484
	}
	if ch >= 1 && ch <= 13 {
		return 2407 + ch*5
	}
	return 0
}

// snrGrade converts an SNR (dB) into a quick letter grade.
func snrGrade(snr float64) string {
	switch {
	case snr >= 40:
		return "A+"
	case snr >= 25:
		return "A"
	case snr >= 20:
		return "B"
	case snr >= 15:
		return "C"
	case snr >= 10:
		return "D"
	default:
		return "F"
	}
}

// ---- generic TLV walking ----

// TLV is a type/length/value element.
type TLV struct {
	Type   int
	Length int
	Value  []byte
	Offset int
}

// walkTLV parses 1-byte-type, 1-byte-length TLVs (802.11 IE style).
func walkTLV(b []byte) []TLV {
	var out []TLV
	i := 0
	for i+2 <= len(b) {
		t := int(b[i])
		l := int(b[i+1])
		if i+2+l > len(b) {
			break
		}
		out = append(out, TLV{Type: t, Length: l, Value: b[i+2 : i+2+l], Offset: i})
		i += 2 + l
	}
	return out
}

// walkTLV16 parses 1-byte-type, 2-byte-LE-length TLVs.
func walkTLV16(b []byte) []TLV {
	var out []TLV
	i := 0
	for i+3 <= len(b) {
		t := int(b[i])
		l := int(binary.LittleEndian.Uint16(b[i+1:]))
		if i+3+l > len(b) {
			break
		}
		out = append(out, TLV{Type: t, Length: l, Value: b[i+3 : i+3+l], Offset: i})
		i += 3 + l
	}
	return out
}

// ---- geo export (for location-bearing tools) ----

// GeoPoint is a labelled coordinate.
type GeoPoint struct {
	Name string
	Lat  float64
	Lon  float64
	Desc string
}

func exportKML(pts []GeoPoint) string {
	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	sb.WriteString("<kml xmlns=\"http://www.opengis.net/kml/2.2\"><Document>\n")
	for _, p := range pts {
		sb.WriteString("  <Placemark>\n")
		sb.WriteString("    <name>" + xmlEsc(p.Name) + "</name>\n")
		sb.WriteString("    <description>" + xmlEsc(p.Desc) + "</description>\n")
		sb.WriteString(fmt.Sprintf("    <Point><coordinates>%f,%f,0</coordinates></Point>\n", p.Lon, p.Lat))
		sb.WriteString("  </Placemark>\n")
	}
	sb.WriteString("</Document></kml>\n")
	return sb.String()
}
func exportGeoJSON(pts []GeoPoint) string {
	type feat struct {
		Type       string                 `json:"type"`
		Geometry   map[string]interface{} `json:"geometry"`
		Properties map[string]interface{} `json:"properties"`
	}
	var feats []feat
	for _, p := range pts {
		feats = append(feats, feat{
			Type:       "Feature",
			Geometry:   map[string]interface{}{"type": "Point", "coordinates": []float64{p.Lon, p.Lat}},
			Properties: map[string]interface{}{"name": p.Name, "desc": p.Desc},
		})
	}
	doc := map[string]interface{}{"type": "FeatureCollection", "features": feats}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}
func xmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// haversineKm returns great-circle distance in kilometres.
func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const Rk = 6371.0
	toRad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat := toRad(lat2 - lat1)
	dLon := toRad(lon2 - lon1)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(toRad(lat1))*math.Cos(toRad(lat2))*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return Rk * c
}

// ---- additional crypto ----

// aesCCMDecrypt performs AES-CCM* decryption+MIC verification (Zigbee/802.15.4/LoRa style).
func aesCCMEncrypt(key, nonce, plaintext, aad []byte, micLen int) ([]byte, []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil
	}
	bs := 16
	// CBC-MAC with B0
	L := 15 - len(nonce)
	if L < 2 {
		L = 2
	}
	b0 := make([]byte, bs)
	flags := byte(0)
	if len(aad) > 0 {
		flags |= 0x40
	}
	flags |= byte(((micLen - 2) / 2) << 3)
	flags |= byte(L - 1)
	b0[0] = flags
	copy(b0[1:], nonce)
	putLen(b0[bs-L:], len(plaintext))
	x := make([]byte, bs)
	cbc := func(blk []byte) {
		y := xorBytes(x, blk)
		block.Encrypt(x, y)
	}
	cbc(b0)
	if len(aad) > 0 {
		var hdr []byte
		if len(aad) < 0xFF00 {
			hdr = make([]byte, 2)
			binary.BigEndian.PutUint16(hdr, uint16(len(aad)))
		} else {
			hdr = make([]byte, 6)
			hdr[0] = 0xFF
			hdr[1] = 0xFE
			binary.BigEndian.PutUint32(hdr[2:], uint32(len(aad)))
		}
		full := append(append([]byte{}, hdr...), aad...)
		for len(full)%bs != 0 {
			full = append(full, 0)
		}
		for i := 0; i < len(full); i += bs {
			cbc(full[i : i+bs])
		}
	}
	pt := append([]byte{}, plaintext...)
	for len(pt)%bs != 0 {
		pt = append(pt, 0)
	}
	for i := 0; i < len(pt); i += bs {
		cbc(pt[i : i+bs])
	}
	mic := append([]byte{}, x[:micLen]...)
	// CTR encryption
	ctr := make([]byte, bs)
	ctr[0] = byte(L - 1)
	copy(ctr[1:], nonce)
	s := cipher.NewCTR(block, ctr) // S0 used for MIC then stream
	_ = s
	// Build keystream manually (S0 for MIC, S1.. for data)
	ct := make([]byte, len(plaintext))
	a := make([]byte, bs)
	a[0] = byte(L - 1)
	copy(a[1:], nonce)
	sb := make([]byte, bs)
	// S0 for MIC
	block.Encrypt(sb, a)
	for i := range mic {
		mic[i] ^= sb[i]
	}
	ctrVal := 1
	for i := 0; i < len(plaintext); i += bs {
		putLen(a[bs-L:], ctrVal)
		block.Encrypt(sb, a)
		for j := 0; j < bs && i+j < len(plaintext); j++ {
			ct[i+j] = plaintext[i+j] ^ sb[j]
		}
		ctrVal++
	}
	return ct, mic
}
func putLen(dst []byte, v int) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(v & 0xFF)
		v >>= 8
	}
}

func sha512hex(b []byte) string {
	h := sha512.Sum512(b)
	return hex.EncodeToString(h[:])
}

// clampInt bounds v to [lo,hi].
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// humanBytes formats a byte count.
func humanBytes(n int) string {
	f := float64(n)
	units := []string{"B", "KB", "MB", "GB"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// ============================ SHARED 802.11 MAC LAYER ============================
// A compact IEEE 802.11 MAC-header dissector shared by the Wi-Fi tools.

type Dot11 struct {
	Version   int
	Type      int
	Subtype   int
	ToDS      bool
	FromDS    bool
	MoreFrag  bool
	Retry     bool
	PwrMgmt   bool
	MoreData  bool
	Protected bool
	Order     bool
	Duration  uint16
	Addr1     []byte // RA / DA
	Addr2     []byte // TA / SA
	Addr3     []byte // BSSID
	Seq       uint16
	Frag      int
	Body      []byte
	OK        bool
}

var dot11TypeName = map[int]string{0: "Management", 1: "Control", 2: "Data", 3: "Extension"}

var dot11MgmtSubtype = map[int]string{
	0:  "Association Request",
	1:  "Association Response",
	2:  "Reassociation Request",
	3:  "Reassociation Response",
	4:  "Probe Request",
	5:  "Probe Response",
	6:  "Timing Advertisement",
	8:  "Beacon",
	9:  "ATIM",
	10: "Disassociation",
	11: "Authentication",
	12: "Deauthentication",
	13: "Action",
	14: "Action No Ack",
}
var dot11CtrlSubtype = map[int]string{
	2:  "Trigger",
	4:  "Beamforming Report Poll",
	5:  "VHT/HE NDP Announcement",
	6:  "Control Frame Extension",
	7:  "Control Wrapper",
	8:  "Block Ack Request",
	9:  "Block Ack",
	10: "PS-Poll",
	11: "RTS",
	12: "CTS",
	13: "ACK",
	14: "CF-End",
	15: "CF-End + CF-Ack",
}
var dot11DataSubtype = map[int]string{
	0:  "Data",
	1:  "Data + CF-Ack",
	2:  "Data + CF-Poll",
	4:  "Null (no data)",
	8:  "QoS Data",
	9:  "QoS Data + CF-Ack",
	10: "QoS Data + CF-Poll",
	12: "QoS Null",
}

// dot11SubtypeName resolves a readable subtype for a frame.
func dot11SubtypeName(typ, sub int) string {
	switch typ {
	case 0:
		if n, ok := dot11MgmtSubtype[sub]; ok {
			return n
		}
	case 1:
		if n, ok := dot11CtrlSubtype[sub]; ok {
			return n
		}
	case 2:
		if n, ok := dot11DataSubtype[sub]; ok {
			return n
		}
	}
	return fmt.Sprintf("Subtype-%d", sub)
}

// 802.11 reason codes (subset of IEEE Std 802.11 Table 9-45).
var dot11ReasonCode = map[int]string{
	0:  "Reserved",
	1:  "Unspecified",
	2:  "Previous auth no longer valid",
	3:  "Deauth: leaving/left",
	4:  "Disassoc: inactivity",
	5:  "Disassoc: AP overloaded",
	6:  "Class-2 frame from nonauth STA",
	7:  "Class-3 frame from nonassoc STA",
	8:  "Disassoc: leaving BSS",
	9:  "STA not authenticated",
	10: "Power capability unacceptable",
	11: "Supported channels unacceptable",
	13: "Invalid information element",
	14: "MIC failure",
	15: "4-Way Handshake timeout",
	16: "Group Key Handshake timeout",
	17: "4-Way IE mismatch",
	18: "Invalid group cipher",
	19: "Invalid pairwise cipher",
	20: "Invalid AKMP",
	21: "Unsupported RSN version",
	22: "Invalid RSN capabilities",
	23: "802.1X auth failed",
	24: "Cipher suite rejected by policy",
	34: "Disassoc: low ACK / QoS",
}

// 802.11 status codes (subset).
var dot11StatusCode = map[int]string{
	0:  "Success",
	1:  "Unspecified failure",
	10: "Capabilities unsupported",
	11: "Reassoc denied (no assoc)",
	12: "Assoc denied (other reason)",
	13: "Auth algorithm unsupported",
	14: "Auth out of sequence",
	15: "Auth challenge failure",
	16: "Auth timeout",
	17: "AP out of capacity",
	18: "Unsupported basic rates",
	40: "Invalid information element",
	43: "Invalid pairwise cipher",
	44: "Invalid AKMP",
}

// parseDot11 dissects a MAC header from an 802.11 frame body.
func parseDot11(b []byte) Dot11 {
	var d Dot11
	if len(b) < 10 {
		return d
	}
	fc := binary.LittleEndian.Uint16(b[0:2])
	d.Version = int(fc & 0x3)
	d.Type = int((fc >> 2) & 0x3)
	d.Subtype = int((fc >> 4) & 0xF)
	d.ToDS = fc&0x0100 != 0
	d.FromDS = fc&0x0200 != 0
	d.MoreFrag = fc&0x0400 != 0
	d.Retry = fc&0x0800 != 0
	d.PwrMgmt = fc&0x1000 != 0
	d.MoreData = fc&0x2000 != 0
	d.Protected = fc&0x4000 != 0
	d.Order = fc&0x8000 != 0
	d.Duration = binary.LittleEndian.Uint16(b[2:4])
	d.Addr1 = b[4:10]
	if len(b) >= 16 {
		d.Addr2 = b[10:16]
	}
	if len(b) >= 22 {
		d.Addr3 = b[16:22]
		sc := binary.LittleEndian.Uint16(b[22:24])
		d.Seq = sc >> 4
		d.Frag = int(sc & 0xF)
	}
	hdrLen := 24
	if d.Type == 0 && d.Subtype == 8 { // beacon has fixed params before IEs handled by caller
		if len(b) > hdrLen {
			d.Body = b[hdrLen:]
		}
	} else if len(b) > hdrLen {
		d.Body = b[hdrLen:]
	}
	d.OK = true
	return d
}

// rsnAKM / rsnCipher suite selector names (00-0F-AC OUI).
func rsnCipherName(sel uint32) string {
	switch sel & 0xFF {
	case 0:
		return "Use group"
	case 1:
		return "WEP-40"
	case 2:
		return "TKIP"
	case 4:
		return "CCMP-128"
	case 5:
		return "WEP-104"
	case 8:
		return "GCMP-128"
	case 9:
		return "GCMP-256"
	case 10:
		return "CCMP-256"
	}
	return fmt.Sprintf("cipher-%d", sel&0xFF)
}
func rsnAKMName(sel uint32) string {
	switch sel & 0xFF {
	case 1:
		return "802.1X"
	case 2:
		return "PSK"
	case 3:
		return "FT-802.1X"
	case 4:
		return "FT-PSK"
	case 5:
		return "802.1X-SHA256"
	case 6:
		return "PSK-SHA256"
	case 8:
		return "SAE (WPA3)"
	case 9:
		return "FT-SAE"
	case 11:
		return "802.1X-Suite-B"
	case 12:
		return "802.1X-Suite-B-192"
	case 18:
		return "OWE"
	}
	return fmt.Sprintf("akm-%d", sel&0xFF)
}

// ouiVendor is a small IEEE OUI->vendor map (common Wi-Fi/IoT vendors).
var ouiVendor = map[string]string{
	"00:03:7f": "Atheros",
	"00:0c:43": "Ralink",
	"00:13:10": "Cisco-Linksys",
	"00:14:bf": "Cisco-Linksys",
	"00:16:b6": "Cisco-Linksys",
	"00:18:4d": "Netgear",
	"00:1a:11": "Google",
	"00:1b:63": "Apple",
	"00:1d:0f": "TP-Link",
	"00:1e:58": "D-Link",
	"00:21:29": "Cisco-Linksys",
	"00:23:69": "Cisco-Linksys",
	"00:25:9c": "Cisco-Linksys",
	"00:26:bb": "Apple",
	"00:50:f2": "Microsoft",
	"00:90:4c": "Epigram",
	"08:00:27": "VirtualBox",
	"18:fe:34": "Espressif",
	"24:a4:3c": "Ubiquiti",
	"28:6c:07": "Xiaomi",
	"2c:f0:5d": "Micro-Star",
	"3c:5a:b4": "Google",
	"40:9f:38": "AzureWave",
	"44:65:0d": "Amazon",
	"50:c7:bf": "TP-Link",
	"5c:cf:7f": "Espressif",
	"68:ff:7b": "TP-Link",
	"74:da:38": "Edimax",
	"7c:df:a1": "Espressif",
	"84:16:f9": "TP-Link",
	"8c:85:90": "Apple",
	"90:9a:4a": "TP-Link",
	"ac:22:0b": "ASUSTek",
	"b0:4e:26": "TP-Link",
	"b8:27:eb": "Raspberry Pi",
	"c8:3a:35": "Tenda",
	"d8:3a:dd": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
	"f0:9f:c2": "Ubiquiti",
	"fc:ec:da": "Ubiquiti",
}

func ouiLookup(mac string) string {
	if len(mac) < 8 {
		return "Unknown"
	}
	p := strings.ToLower(mac[:8])
	if v, ok := ouiVendor[p]; ok {
		return v
	}
	return "Unknown"
}

// ============================ OGPSSpoofChk DOMAIN ENGINE ============================
// Offline GNSS spoofing detector. Parses NMEA 0183 logs (GGA/RMC/GSV/GSA/VTG/GLL),
// reconstructs the track, and flags spoofing indicators: impossible speed, position
// jumps, time anomalies, altitude jumps, suspiciously uniform/high C/N0, and
// implausible satellite geometry. Pure stdlib; reads an NMEA text file.

const MITREID = "T0830 / T1557 (GNSS spoofing detection, authorized testing)"

// NMEA talker IDs.
var nmeaTalker = map[string]string{
	"GP": "GPS", "GL": "GLONASS", "GA": "Galileo", "GB": "BeiDou",
	"GQ": "QZSS", "GN": "GNSS (combined)", "GI": "IRNSS/NavIC",
}

type gpsFix struct {
	Line    int
	Time    string
	Lat     float64
	Lon     float64
	AltM    float64
	SpeedKn float64
	CourseD float64
	Sats    int
	HDOP    float64
	FixQual int
	Valid   bool
	Source  string
}

type gsvSat struct {
	PRN  int
	Elev int
	Azim int
	CN0  int // dB-Hz
}

func nmeaChecksum(sentence string) (string, string, bool) {
	// sentence like $GPGGA,...*4F
	body := strings.TrimPrefix(sentence, "$")
	star := strings.LastIndex(body, "*")
	if star < 0 {
		return body, "", false
	}
	payload := body[:star]
	want := strings.ToUpper(strings.TrimSpace(body[star+1:]))
	var cs byte
	for i := 0; i < len(payload); i++ {
		cs ^= payload[i]
	}
	got := fmt.Sprintf("%02X", cs)
	return payload, want, got == want
}

func parseNMEALat(val, hemi string) float64 {
	if val == "" {
		return 0
	}
	f, _ := strconv.ParseFloat(val, 64)
	deg := math.Floor(f / 100)
	min := f - deg*100
	d := deg + min/60
	if hemi == "S" {
		d = -d
	}
	return d
}
func parseNMEALon(val, hemi string) float64 {
	if val == "" {
		return 0
	}
	f, _ := strconv.ParseFloat(val, 64)
	deg := math.Floor(f / 100)
	min := f - deg*100
	d := deg + min/60
	if hemi == "W" {
		d = -d
	}
	return d
}

type gnssLog struct {
	Fixes   []gpsFix
	Sats    []gsvSat
	Bad     int
	Talkers map[string]bool
}

func parseNMEA(b []byte) gnssLog {
	log := gnssLog{Talkers: map[string]bool{}}
	lines := strings.Split(string(b), "\n")
	var cur *gpsFix
	for i, ln := range lines {
		// Sentences may follow binary bytes (pcap / pcapng of NMEA over UDP or
		// TCP, e.g. gpsd), so start at the last '$' on the line.
		k := strings.LastIndexByte(ln, '$')
		if k < 0 {
			continue
		}
		ln = strings.TrimSpace(ln[k:])
		payload, _, ok := nmeaChecksum(ln)
		if !ok && strings.Contains(ln, "*") {
			log.Bad++
		}
		fields := strings.Split(payload, ",")
		if len(fields) == 0 {
			continue
		}
		tag := fields[0]
		if len(tag) >= 2 {
			log.Talkers[nmeaTalker[tag[:2]]] = true
		}
		sentence := tag
		if len(tag) >= 5 {
			sentence = tag[2:]
		}
		switch sentence {
		case "GGA":
			if len(fields) >= 10 {
				f := gpsFix{Line: i + 1, Source: "GGA"}
				f.Time = fields[1]
				f.Lat = parseNMEALat(fields[2], fields[3])
				f.Lon = parseNMEALon(fields[4], fields[5])
				f.FixQual, _ = strconv.Atoi(fields[6])
				f.Sats, _ = strconv.Atoi(fields[7])
				f.HDOP, _ = strconv.ParseFloat(fields[8], 64)
				f.AltM, _ = strconv.ParseFloat(fields[9], 64)
				f.Valid = f.FixQual > 0
				log.Fixes = append(log.Fixes, f)
				cur = &log.Fixes[len(log.Fixes)-1]
			}
		case "RMC":
			if len(fields) >= 8 {
				f := gpsFix{Line: i + 1, Source: "RMC"}
				f.Time = fields[1]
				f.Valid = fields[2] == "A"
				f.Lat = parseNMEALat(fields[3], fields[4])
				f.Lon = parseNMEALon(fields[5], fields[6])
				f.SpeedKn, _ = strconv.ParseFloat(fields[7], 64)
				if len(fields) >= 9 {
					f.CourseD, _ = strconv.ParseFloat(fields[8], 64)
				}
				log.Fixes = append(log.Fixes, f)
				cur = &log.Fixes[len(log.Fixes)-1]
			}
		case "VTG":
			if cur != nil && len(fields) >= 6 {
				sp, _ := strconv.ParseFloat(fields[5], 64)
				if sp > 0 {
					cur.SpeedKn = sp
				}
			}
		case "GSA":
			if cur != nil && len(fields) >= 17 {
				h, _ := strconv.ParseFloat(fields[16], 64)
				if h > 0 {
					cur.HDOP = h
				}
			}
		case "GSV":
			// $xxGSV,total,msg,numSats,(prn,elev,azim,cn0)x4
			if len(fields) >= 4 {
				for base := 4; base+3 < len(fields); base += 4 {
					prn, _ := strconv.Atoi(fields[base])
					el, _ := strconv.Atoi(fields[base+1])
					az, _ := strconv.Atoi(fields[base+2])
					cnStr := fields[base+3]
					cn, _ := strconv.Atoi(cnStr)
					if prn != 0 {
						log.Sats = append(log.Sats, gsvSat{PRN: prn, Elev: el, Azim: az, CN0: cn})
					}
				}
			}
		case "GLL":
			if len(fields) >= 6 {
				f := gpsFix{Line: i + 1, Source: "GLL"}
				f.Lat = parseNMEALat(fields[1], fields[2])
				f.Lon = parseNMEALon(fields[3], fields[4])
				f.Time = fields[5]
				f.Valid = len(fields) >= 7 && fields[6] == "A"
				log.Fixes = append(log.Fixes, f)
			}
		}
	}
	return log
}

func loadGNSS(src string, demo bool) (gnssLog, error) {
	if demo {
		return parseNMEA([]byte(demoNMEA())), nil
	}
	b, err := loadBytes(src)
	if err != nil {
		return gnssLog{}, err
	}
	return parseNMEA(b), nil
}

func demoNMEA() string {
	// Normal track near NYC, then a sudden teleport to London (spoof), with
	// uniform high C/N0 and a time glitch.
	lines := []string{
		"$GPGGA,120000.00,4044.9000,N,07359.9000,W,1,09,0.9,10.0,M,,M,,*5E",
		"$GPRMC,120000.00,A,4044.9000,N,07359.9000,W,2.0,090.0,010126,,,A*4C",
		"$GPGGA,120001.00,4044.9010,N,07359.8990,W,1,09,0.9,10.1,M,,M,,*5E",
		"$GPRMC,120001.00,A,4044.9010,N,07359.8990,W,2.1,090.0,010126,,,A*4C",
		"$GPGGA,120002.00,4044.9020,N,07359.8980,W,1,09,1.0,10.2,M,,M,,*54",
		"$GPGSV,3,1,11,01,45,100,48,02,40,110,48,03,35,120,48,04,30,130,48*7F",
		"$GPGSV,3,2,11,05,25,140,48,06,20,150,48,07,15,160,48,08,10,170,48*74",
		"$GPRMC,120003.00,A,5130.0000,N,00007.0000,W,2.0,090.0,010126,,,A*43",
		"$GPGGA,120003.00,5130.0000,N,00007.0000,W,1,12,0.5,25.0,M,,M,,*51",
		"$GPGGA,120001.00,5130.0100,N,00007.0100,W,1,12,0.5,250.0,M,,M,,*63",
	}
	return strings.Join(lines, "\n") + "\n"
}

func analyze(src string, demo bool) *Report {
	r := newReport(src)
	if demo {
		r.Source = "[synthetic NMEA with spoof teleport]"
	}
	log, err := loadGNSS(src, demo)
	if err != nil {
		r.note("load error: " + err.Error())
		r.grade()
		return r
	}
	r.stat("Fixes parsed", strconv.Itoa(len(log.Fixes)))
	r.stat("GSV satellites", strconv.Itoa(len(log.Sats)))
	r.stat("Bad checksums", strconv.Itoa(log.Bad))
	var talkers []string
	for t := range log.Talkers {
		if t != "" {
			talkers = append(talkers, t)
		}
	}
	sort.Strings(talkers)
	r.stat("Constellations", strings.Join(talkers, ", "))

	if len(log.Fixes) == 0 {
		r.add(Finding{Title: "No fixes", Sev: SevInfo, Desc: "No position fixes parsed from NMEA.", Mitre: []string{}})
		r.grade()
		return r
	}

	// track table + geo points
	tt := Table{Title: "Track", Headers: []string{"#", "Time", "Lat", "Lon", "Alt(m)", "Spd(kn)", "Sats", "HDOP", "Valid"}}
	var pts []GeoPoint
	for i, f := range log.Fixes {
		tt.Rows = append(tt.Rows, []string{
			strconv.Itoa(i), f.Time, fmt.Sprintf("%.5f", f.Lat), fmt.Sprintf("%.5f", f.Lon),
			fmt.Sprintf("%.1f", f.AltM), fmt.Sprintf("%.1f", f.SpeedKn), strconv.Itoa(f.Sats),
			fmt.Sprintf("%.1f", f.HDOP), yn(f.Valid),
		})
		pts = append(pts, GeoPoint{Name: "fix" + strconv.Itoa(i), Lat: f.Lat, Lon: f.Lon, Desc: f.Time})
	}
	r.addTable(tt)
	r.note("KML export available via geo helpers (" + strconv.Itoa(len(pts)) + " points)")

	gpsFindings(r, log)
	r.grade()
	return r
}
func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func gpsFindings(r *Report, log gnssLog) {
	fixes := log.Fixes
	// position jump / impossible speed between consecutive fixes
	for i := 1; i < len(fixes); i++ {
		a := fixes[i-1]
		b := fixes[i]
		if a.Lat == 0 && a.Lon == 0 {
			continue
		}
		if b.Lat == 0 && b.Lon == 0 {
			continue
		}
		dist := haversineKm(a.Lat, a.Lon, b.Lat, b.Lon)
		rawDT := nmeaTimeDelta(a.Time, b.Time)
		dt := rawDT
		if dt <= 0 {
			dt = 1
		}
		speedKmh := dist / (dt / 3600.0)
		if dist > 5 && speedKmh > 3000 { // faster than any airliner
			r.add(Finding{Title: "Impossible speed / teleport", Sev: SevCrit,
				Desc: fmt.Sprintf("Position jumped %.1f km in %.0fs (%.0f km/h) between fix %d and %d — physically impossible, a classic spoof indicator.", dist, dt, speedKmh, i-1, i),
				Loc:  fmt.Sprintf("fix#%d->%d", i-1, i), Mitre: []string{"T0830"},
				Rec: "Treat the receiver as compromised; cross-check with inertial/clock sources."})
		}
		// time going backwards
		if rawDT < 0 && len(a.Time) >= 6 && len(b.Time) >= 6 {
			r.add(Finding{Title: "Time anomaly (clock rollback)", Sev: SevHigh,
				Desc:  fmt.Sprintf("Timestamp decreased between fix %d (%s) and %d (%s) — spoofers often misorder/rewind GNSS time.", i-1, a.Time, i, b.Time),
				Mitre: []string{"T0830"}, Rec: "Validate GNSS time against an independent NTP/RTC source."})
		}
		// altitude jump
		if math.Abs(b.AltM-a.AltM) > 100 && dt < 5 {
			r.add(Finding{Title: "Altitude discontinuity", Sev: SevMed,
				Desc:  fmt.Sprintf("Altitude changed %.0f m in %.0fs between fix %d and %d.", b.AltM-a.AltM, dt, i-1, i),
				Mitre: []string{"T0830"}, Rec: "Correlate with barometric altimeter if available."})
		}
	}
	// uniform / high C/N0 across satellites (spoofer often transmits all sats at equal power)
	if len(log.Sats) >= 4 {
		var cn []float64
		for _, s := range log.Sats {
			if s.CN0 > 0 {
				cn = append(cn, float64(s.CN0))
			}
		}
		if len(cn) >= 4 {
			sd := statStdDev(cn)
			mean := statMean(cn)
			if sd < 1.5 && mean > 45 {
				r.add(Finding{Title: "Uniform high C/N0", Sev: SevHigh,
					Desc:  fmt.Sprintf("All %d satellites report nearly identical C/N0 (mean %.0f dB-Hz, stddev %.1f). Real constellations vary with elevation; uniform strong signals indicate a single spoofing transmitter.", len(cn), mean, sd),
					Mitre: []string{"T0830"}, Rec: "Use a multi-antenna/CRPA receiver; flag uniform C/N0 in your GNSS monitor."})
			}
		}
	}
	// HDOP implausibly perfect with teleport
	for _, f := range fixes {
		if f.HDOP > 0 && f.HDOP < 0.6 && f.Sats >= 12 {
			r.add(Finding{Title: "Suspiciously perfect geometry", Sev: SevLow,
				Desc:  fmt.Sprintf("Fix at line %d reports HDOP %.1f with %d sats — unusually ideal, sometimes seen in simulator/spoofer output.", f.Line, f.HDOP, f.Sats),
				Mitre: []string{"T0830"}, Rec: "Corroborate with raw pseudorange residuals if available."})
			break
		}
	}
	if log.Bad > 0 {
		r.add(Finding{Title: "NMEA checksum failures", Sev: SevLow,
			Desc:  fmt.Sprintf("%d sentence(s) failed checksum — log corruption or injection.", log.Bad),
			Mitre: []string{"T0830"}, Rec: "Verify the logging chain integrity."})
	}
	hasCrit := false
	for _, f := range r.Findings {
		if f.Sev == SevCrit || f.Sev == SevHigh {
			hasCrit = true
		}
	}
	if !hasCrit {
		r.add(Finding{Title: "No strong spoofing indicators", Sev: SevInfo,
			Desc: "Track kinematics, timing and C/N0 appear consistent with genuine GNSS.", Mitre: []string{"T0830"}})
	}
}

// nmeaTimeDelta returns seconds between two hhmmss.ss NMEA times.
func nmeaTimeDelta(a, b string) float64 {
	pa := nmeaSeconds(a)
	pb := nmeaSeconds(b)
	d := pb - pa
	if d < -43200 { // crossed midnight UTC (235959 → 000001), not a rollback
		d += 86400
	}
	return d
}
func nmeaSeconds(t string) float64 {
	if len(t) < 6 {
		return 0
	}
	h, _ := strconv.ParseFloat(t[0:2], 64)
	m, _ := strconv.ParseFloat(t[2:4], 64)
	s, _ := strconv.ParseFloat(t[4:], 64)
	return h*3600 + m*60 + s
}

// ---------- interactive handlers ----------

func handleTalkers() {
	sectionHead("NMEA Talker IDs")
	var keys []string
	for k := range nmeaTalker {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := [][]string{}
	for _, k := range keys {
		rows = append(rows, []string{k, nmeaTalker[k]})
	}
	table([]string{"ID", "Constellation"}, rows)
}
func handleIndicators() {
	sectionHead("Spoofing Indicators Checked")
	rows := [][]string{
		{"Impossible speed", "position jump vs time delta (>3000 km/h)", "CRITICAL"},
		{"Time anomaly", "GNSS timestamp rewind", "HIGH"},
		{"Uniform high C/N0", "all sats equal strong power", "HIGH"},
		{"Altitude jump", ">100 m in <5 s", "MEDIUM"},
		{"Perfect geometry", "HDOP<0.6 with many sats", "LOW"},
		{"Checksum failures", "corrupt/injected sentences", "LOW"},
	}
	table([]string{"Indicator", "Rule", "Severity"}, rows)
}

var menuDef = []menuEntry{
	{"Analyze NMEA log", "NMEA text or pcap/pcapng: spoof checks", handleRunFile},
	{"Run synthetic spoof demo", "NYC → London teleport, uniform C/N0", handleRunDemo},
	{"NMEA talker IDs", "GP / GL / GA / GB … constellations", handleTalkers},
	{"Spoofing indicators", "Every check and its severity", handleIndicators},
	{"Export report", "txt / md / json / csv / sarif", handleExport},
}

var howtoWarning = "OGPSSpoofChk is for AUTHORIZED GNSS integrity testing only. Analyze logs from receivers you own or are permitted to test. Transmitting GNSS signals is illegal almost everywhere — this tool is OFFLINE and only reads NMEA logs."

var howtoSteps = []string{
	"Record an NMEA 0183 log from the receiver under test (e.g. 'gpspipe -r' or the device's logger).",
	"Run OGPSSpoofChk with no arguments for the TUI, or 'OGPSSpoofChk --input track.nmea' for CLI mode.",
	"Choose 'Analyze NMEA log', or 'Run synthetic spoof demo' to see a teleport/C-N0 case.",
	"Review the Track table (positions, speed, sats, HDOP).",
	"Read FINDINGS: impossible speed, time anomalies, uniform C/N0 and altitude jumps.",
	"Export with 'Export report' or '--format json --output gnss.json'.",
}
var howtoNav = []string{
	"[01] Analyze  — parse NMEA and run spoof checks",
	"[02] Demo  — NYC->London teleport with uniform C/N0",
	"[03] Talker IDs  — GPS/GLONASS/Galileo/BeiDou...",
	"[04] Indicators  — the checks and their severities",
	"[05] Export / [06] HOW TO USE / [00] Exit",
}
var howtoReq = []string{
	"An NMEA 0183 text log (GGA/RMC/GSV/GSA/VTG/GLL), or a pcap/pcapng of NMEA over UDP/TCP.",
	"No privileges required — analysis is offline.",
	"Include GSV sentences to enable C/N0-based spoof detection.",
}
var howtoNotes = []string{
	"Each NMEA sentence ends with *XX, an XOR checksum over the characters between $ and *; failures suggest corruption/injection.",
	"Lat/Lon are ddmm.mmmm; this tool converts to decimal degrees for haversine distance.",
	"Impossible speed: distance between consecutive fixes over the time delta exceeding ~3000 km/h.",
	"Real satellite C/N0 varies with elevation (20-50 dB-Hz); a spoofer often transmits all PRNs at equal, high power.",
	"Time anomalies (rewound GNSS time) and sudden altitude jumps are additional spoofing tells.",
}

// ============================================================
//  Self-test — exercises NMEA parsing, geo math and the real
//  spoof-detection pipeline on the synthetic demo log.
// ============================================================

func runSelfTest() int {
	pass, fail := 0, 0
	check := func(name string, cond bool, detail string) {
		if cond {
			pass++
			okMsg(name)
		} else {
			fail++
			errMsg(name + " — " + detail)
		}
	}
	sectionHead("OGPSSpoofChk self-test")
	fmt.Println()

	// NMEA checksum on a canonical GPGGA sentence.
	_, _, ok := nmeaChecksum("$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47")
	check("NMEA checksum (GPGGA *47)", ok, "checksum mismatch")
	_, _, bad := nmeaChecksum("$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*00")
	check("NMEA checksum rejects wrong CRC", !bad, "should fail")

	// Coordinate conversion (ddmm.mmmm → decimal degrees).
	lat := parseNMEALat("4807.038", "N")
	check("parseNMEALat 4807.038N≈48.1173", math.Abs(lat-48.1173) < 0.001, fmt.Sprintf("%.4f", lat))
	lon := parseNMEALon("01131.000", "E")
	check("parseNMEALon 01131.000E≈11.5167", math.Abs(lon-11.5167) < 0.001, fmt.Sprintf("%.4f", lon))

	// Haversine NYC → London ≈ 5570 km.
	d := haversineKm(40.7128, -74.0060, 51.5074, -0.1278)
	check("haversine NYC→London ≈5570km", math.Abs(d-5570) < 60, fmt.Sprintf("%.1f", d))

	// Full pipeline on the synthetic spoof log.
	r := analyze("", true)
	check("demo parses fixes", any(r.Stats, "Fixes parsed"), "")
	ids := map[string]bool{}
	worst := 100
	for _, f := range r.Findings {
		ids[f.Title] = true
		if f.Sev == SevCrit {
			worst = 0
		}
	}
	check("teleport finding raised", ids["Impossible speed / teleport"], fmt.Sprint(keys(ids)))
	check("uniform C/N0 finding raised", ids["Uniform high C/N0"], fmt.Sprint(keys(ids)))
	check("clock rollback finding raised", ids["Time anomaly (clock rollback)"], fmt.Sprint(keys(ids)))
	check("demo NMEA checksums all valid", !ids["NMEA checksum failures"], "")
	check("midnight wrap is not a rollback", nmeaTimeDelta("235959.00", "000001.00") == 2, fmt.Sprint(nmeaTimeDelta("235959.00", "000001.00")))
	check("grade reflects CRITICAL spoof", r.Grade == "F" || worst == 0, r.Grade)

	// Statistics helpers.
	xs := []float64{1, 2, 3, 4, 5}
	check("statMean", statMean(xs) == 3, fmt.Sprintf("%.1f", statMean(xs)))
	check("statMedian", statMedian(xs) == 3, fmt.Sprintf("%.1f", statMedian(xs)))

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("All %d checks passed.", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d failed.", pass, fail))
	return 1
}

func any(st []KV, key string) bool {
	for _, k := range st {
		if k.K == key {
			return true
		}
	}
	return false
}
func keys(m map[string]bool) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	sort.Strings(o)
	return o
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OGPSSpoofChk checks GPS / GNSS receiver logs for signs of spoofing (fake satellite signals that move your position or time). It reads NMEA 0183 sentences (GGA, RMC, GSV, GSA, VTG, GLL) from a text log or from a pcap / pcapng capture of NMEA over UDP / TCP (for example gpsd).",
	"It flags impossible jumps in position (faster than an airliner), time going backwards, sudden altitude jumps, all satellites at the same strong signal level (C/N0, a typical spoofer sign), unrealistically perfect geometry and checksum failures. Results come with a track table, a grade and MITRE mapping. It only reads files and never transmits.",
}

var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Start with [1] and give it a log, or try [2] to see a spoofing case. [5] exports the last analysis. [H] opens this help, [0] or q quits.",
	"Record a log with  gpspipe -r > track.nmea  (gpsd), from a serial port with  cat /dev/ttyUSB0 > track.nmea , or with the receiver's own logger. Include GSV sentences: without them the C/N0 check cannot run.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Analyze NMEA log: enter the path of an .nmea / .txt log or a pcap / pcapng. Shows fixes parsed, constellations, bad checksums, the track (time, position, altitude, speed, satellites, HDOP) and the findings."},
	{"2", "Run synthetic spoof demo: a normal track near New York that suddenly jumps to London, with time rewound, an altitude jump and identical satellite power."},
	{"3", "NMEA talker IDs: which prefix means which system (GP = GPS, GL = GLONASS, GA = Galileo, GB = BeiDou, GQ = QZSS, GI = NavIC, GN = combined)."},
	{"4", "Spoofing indicators: every check, its rule and its severity."},
	{"5", "Export report: exports the last analysis (if none, asks for an input file, blank = demo). Choose txt, md, json, csv or sarif and an output file (blank = print to screen)."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "One indicator alone can be a bad antenna or multipath. Several together (jump + uniform C/N0 + time rewind) strongly suggest spoofing."},
	{"*", "Compare GNSS time with an independent clock (NTP or RTC). Spoofers often get time wrong."},
	{"*", "The legal notes and protocol details are on page 3."},
}

func owlHelpCLI() {
	usage()
	pause()
	showHowto()
}
