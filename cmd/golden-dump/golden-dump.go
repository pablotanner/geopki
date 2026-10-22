// cmd/golden-dump/golden-dump.go
// Dumps golden vectors from the reference Go client for the Kotlin port.
// Uses the S2 approximator (same as the wasm client), so no GDAL/cgo needed.
//
//   go run ./cmd/golden-dump -address http://localhost:8080 -out golden.json
package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"geopki/pkg/bitstring"
	"geopki/pkg/comm"
	"geopki/pkg/crypto"

	"google.golang.org/protobuf/proto"
)

const fGrow = 1

type point struct {
	Name   string  `json:"name"`
	Lon    float64 `json:"lon"`
	Lat    float64 `json:"lat"`
	Alt    float64 `json:"alt"`
	Radius uint64  `json:"radius"`
}

var points = []point{
	{"eth-cab", 8.5490, 47.3786, 470, 50},
	{"zurich-hb", 8.5402, 47.3779, 410, 100},
	{"empty-area", 9.2000, 46.1000, 1500, 50},
	{"radius-0", 8.5490, 47.3786, 470, 0},
	{"radius-max", 8.5490, 47.3786, 470, 253},
	{"antimeridian-east", 180, 0, 0, 20},
	{"antimeridian-west", -180, 0, 0, 20},
	{"south-pole", 0, -90, 2800, 20},
	{"alt-min", 8.5490, 47.3786, float64(bitstring.D), 10},
	{"alt-max", 8.5490, 47.3786, float64(bitstring.H), 10},
	// must be rejected
	{"err-radius", 8.5490, 47.3786, 470, 254},
	{"err-lon", 180.0001, 0, 0, 10},
	{"err-alt", 8.5490, 47.3786, float64(bitstring.D) - 1, 10},
}

type xyBits struct {
	Bits string `json:"bits"` // uint64 as 16 hex chars; bit 63 may be set -> ULong in Kotlin
	Len  uint8  `json:"len"`
}

type queryVec struct {
	point
	XY         []xyBits `json:"xy,omitempty"` // sorted by (bits, len)
	MinAlt     int16    `json:"minAlt"`
	MaxAlt     int16    `json:"maxAlt"`
	RequestB64 string   `json:"requestB64,omitempty"` // request built from the sorted list
	Stable     bool     `json:"stable"`               // same set over repeated runs?
	Err        string   `json:"err,omitempty"`
}

type proofVec struct {
	Name        string   `json:"name"`
	Query       string   `json:"query"` // queryVec name it is verified against
	ResponseB64 string   `json:"responseB64"`
	Accept      bool     `json:"accept"`
	CertHashes  []string `json:"certHashes,omitempty"` // sorted
	Err         string   `json:"err,omitempty"`
}

type golden struct {
	PublicKeyB64 string     `json:"publicKeyB64"`
	Queries      []queryVec `json:"queries"`
	Proofs       []proofVec `json:"proofs"`
}

var b64 = base64.StdEncoding.EncodeToString

func newQuery(p point) (*comm.Query, error) {
	q, err := comm.NewQuery(p.Lon, p.Lat, p.Alt, p.Radius, fGrow, &comm.S2CircleApproximator{})
	if err != nil {
		return nil, err
	}
	// upstream returns the set via map iteration -> random order
	sort.Slice(q.XYBitStrings, func(i, j int) bool {
		a, b := q.XYBitStrings[i], q.XYBitStrings[j]
		if a.XYBitString != b.XYBitString {
			return a.XYBitString < b.XYBitString
		}
		return a.XYBitStringLen < b.XYBitStringLen
	})
	return q, nil
}

func canon(q *comm.Query) string {
	var sb strings.Builder
	for _, b := range q.XYBitStrings {
		fmt.Fprintf(&sb, "%016x/%d,", b.XYBitString, b.XYBitStringLen)
	}
	return sb.String()
}

func buildQuery(p point) (*comm.Query, queryVec) {
	v := queryVec{point: p}
	q, err := newQuery(p)
	if err != nil {
		v.Err = err.Error()
		return nil, v
	}
	v.Stable = true
	for i := 0; i < 20; i++ {
		if again, _ := newQuery(p); canon(again) != canon(q) {
			v.Stable = false
			break
		}
	}
	req := &comm.Request{MinAltitude: uint32(q.MinAltitude), MaxAltitude: uint32(q.MaxAltitude)}
	for _, b := range q.XYBitStrings {
		v.XY = append(v.XY, xyBits{fmt.Sprintf("%016x", b.XYBitString), b.XYBitStringLen})
		req.XYBitStrings = append(req.XYBitStrings,
			&comm.XYBitString{XYBitString: b.XYBitString, XYBitStringLen: uint32(b.XYBitStringLen)})
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}
	v.RequestB64 = b64(raw)
	v.MinAlt, v.MaxAlt = q.MinAltitude, q.MaxAltitude
	return q, v
}

// full client-side check, same as cmd/geopki-client
func verify(r *comm.Response, q *comm.Query, pk *ecdsa.PublicKey) (bool, []string, string) {
	hashes, err := crypto.VerifyResponse(r, q, pk)
	if err == nil {
		err = crypto.EnsureConsistency(r, pk)
	}
	if err != nil {
		return false, nil, err.Error()
	}
	hs := hashes.ToSlice()
	sort.Strings(hs)
	return true, hs, ""
}

func flip(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	b[len(b)-1] ^= 0x01
	return true
}

// each returns false if not applicable to this response
var mutations = []struct {
	name  string
	apply func(*comm.Response) bool
}{
	{"smh-sig-flip", func(r *comm.Response) bool { return r.SignedMapHead != nil && flip(r.SignedMapHead.Signature) }},
	{"smh-root-flip", func(r *comm.Response) bool { return r.SignedMapHead != nil && flip(r.SignedMapHead.RootHash) }},
	{"sch-sig-flip", func(r *comm.Response) bool {
		return r.SignedConsistencyHead != nil && flip(r.SignedConsistencyHead.Signature)
	}},
	{"inclusion-proof-flip", func(r *comm.Response) bool { return flip(r.InclusionProof) }},
	{"drop-last-node", func(r *comm.Response) bool {
		if len(r.Nodes) < 2 {
			return false
		}
		r.Nodes = r.Nodes[:len(r.Nodes)-1]
		return true
	}},
	{"child-hash-flip", func(r *comm.Response) bool {
		for _, n := range r.Nodes {
			if flip(n.XYLeftChildHash) || flip(n.ZLeftChildHash) {
				return true
			}
		}
		return false
	}},
	{"cert-hash-flip", func(r *comm.Response) bool {
		for _, n := range r.Nodes {
			if len(n.CertificateHashes) > 0 {
				return flip(n.CertificateHashes[0])
			}
		}
		return false
	}},
	// omission: server hides a GeoCert (downgrade CONFLICT -> UNVERIFIED)
	{"cert-hash-drop", func(r *comm.Response) bool {
		for _, n := range r.Nodes {
			if len(n.CertificateHashes) > 0 {
				n.CertificateHashes = n.CertificateHashes[1:]
				return true
			}
		}
		return false
	}},
}

func main() {
	addr := flag.String("address", "http://127.0.0.1:1234", "map server address")
	out := flag.String("out", "golden.json", "output file")
	pointsFile := flag.String("points", "", "optional JSON file with query points (overrides built-in list)")
	flag.Parse()

	if *pointsFile != "" {
		raw, err := os.ReadFile(*pointsFile)
		if err != nil {
			log.Fatal(err)
		}
		points = nil
		if err := json.Unmarshal(raw, &points); err != nil {
			log.Fatalf("parsing %s: %v", *pointsFile, err)
		}
	}

	resp, err := http.Get(*addr + "/v1/public-key")
	if err != nil {
		log.Fatal(err)
	}
	pkDER, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	pkAny, err := x509.ParsePKIXPublicKey(pkDER)
	if err != nil {
		log.Fatal(err)
	}
	pk := pkAny.(*ecdsa.PublicKey)

	g := golden{PublicKeyB64: b64(pkDER)}

	type built struct {
		p point
		q *comm.Query
	}
	var ok []built
	for _, p := range points {
		q, v := buildQuery(p)
		g.Queries = append(g.Queries, v)
		if q != nil {
			ok = append(ok, built{p, q})
		}
	}

	add := func(name string, r *comm.Response, q *comm.Query, qname string) {
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(r)
		if err != nil {
			log.Fatal(err)
		}
		acc, hs, e := verify(r, q, pk)
		g.Proofs = append(g.Proofs, proofVec{name, qname, b64(raw), acc, hs, e})
	}

	for i, b := range ok {
		r, _, _, err := comm.QueryMapServer(*addr, b.q, false)
		if err != nil {
			log.Fatalf("%s: %v", b.p.Name, err)
		}
		add(b.p.Name+"/valid", r, b.q, b.p.Name)
		for _, m := range mutations {
			c := proto.Clone(r).(*comm.Response)
			if m.apply(c) {
				add(b.p.Name+"/"+m.name, c, b.q, b.p.Name)
			}
		}
		if len(ok) > 1 {
			o := ok[(i+1)%len(ok)]
			add(b.p.Name+"/wrong-query", r, o.q, o.p.Name)
		}
	}

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		log.Fatal(err)
	}

	acc := 0
	for _, p := range g.Proofs {
		if p.Accept {
			acc++
		}
	}
	for _, q := range g.Queries {
		if q.Err == "" && !q.Stable {
			log.Printf("WARNING: %s query set not stable across runs", q.Name)
		}
	}
	log.Printf("%d query vectors, %d proof vectors (%d accept, %d reject) -> %s",
		len(g.Queries), len(g.Proofs), acc, len(g.Proofs)-acc, *out)
}