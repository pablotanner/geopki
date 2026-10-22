package crypto

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"geopki/pkg/bitstring"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/golang/geo/s2"
)

// a linear ring as defined in https://www.rfc-editor.org/rfc/rfc7946#section-3.1.6
type LinearRing = [][2]float64

// the first element is a list of exterior rings, the second one a list of interior rings
type ExteriorInteriorRings = [2][]LinearRing

type GeoCertArea struct {
	Coordinates ExteriorInteriorRings `json:"coordinates"`
	Type        string                `json:"type"`
}

// compute S2 loops from a geo cert area
// note that Loops are simply a polygon representation and no computations based on the shape
// is performed in this function
func (area *GeoCertArea) Loops() ([]*s2.Loop, error) {
	if area.Type != "MultiPolygon" {
		return nil, fmt.Errorf("area.Type must be equal to 'MultiPolygon'")
	}

	exteriorRing := area.Coordinates[0]

	loops := make([]*s2.Loop, len(exteriorRing))
	for i, polygon := range exteriorRing {

		// remove last point that is equal to the first and not needed by s2
		polygon = polygon[:len(polygon)-1]

		// array of ccw order points of the loop
		pts := make([]s2.Point, 0, len(polygon))
		// also keep a set of the points to check for duplicate vertices
		certificateStringHashes := mapset.NewThreadUnsafeSet[s2.Point]()

		for i, pt := range polygon {
			// geojson is (longitude, latitude), see https://datatracker.ietf.org/doc/html/rfc7946#section-3.1.1
			p := s2.PointFromLatLng(s2.LatLngFromDegrees(pt[1], pt[0]))

			if i == 0 || !pts[len(pts)-1].ApproxEqual(p) {
				if certificateStringHashes.Contains(p) {
					// Loops are not allowed to have any duplicate vertices (whether adjacent or not).
					// https://pkg.go.dev/github.com/golang/geo@v0.0.0-20230421003525-6adc56603217/s2#Loop
					return nil, fmt.Errorf("loop contains duplicate vertices")
				}

				// add point to the polygon and the set for duplicate checks
				pts = append(pts, p)
				certificateStringHashes.Add(p)
			}
			// otherwise skip this point, equal to the last one -> fix loop
		}

		loops[i] = s2.LoopFromPoints(pts)

		if loops[i].Area() > 12 {
			// fmt.Printf("Warning: changing order of polygon: %s\n", bitstring.LoopToGeoJson(loops[i]))

			// this loop covers almost the whole world, is likely not right-hand rule sorted
			// -> reverse
			for i, j := 0, len(pts)-1; i < j; i, j = i+1, j-1 {
				pts[i], pts[j] = pts[j], pts[i]
			}

			loops[i] = s2.LoopFromPoints(pts)
		}

		err := loops[i].Validate()
		if err != nil {
			fmt.Printf("%s\n", bitstring.LoopToGeoJsonFeature(loops[i]))
			return nil, fmt.Errorf("created invalid loop: %v", err)
		}
	}

	return loops, nil
}

// WiFiAuthMode describes how a client authenticates to the Wi-Fi network.
type WiFiAuthMode string

const (
	WiFiAuthOpen           WiFiAuthMode = "open"
	WiFiAuthWPA2Personal   WiFiAuthMode = "wpa2-personal"
	WiFiAuthWPA3Personal   WiFiAuthMode = "wpa3-personal"
	WiFiAuthWPA2Enterprise WiFiAuthMode = "wpa2-enterprise"
	WiFiAuthWPA3Enterprise WiFiAuthMode = "wpa3-enterprise"
	WiFiAuthWPA3Enterprise192 WiFiAuthMode = "wpa3-enterprise-192"
)

// EAPMethod identifies the inner authentication protocol used by enterprise Wi-Fi.
type EAPMethod string

const (
	EAPTLS  EAPMethod = "eap-tls"
	EAPPEAP EAPMethod = "peap"
	EAPTTLS EAPMethod = "ttls"
)


type WiFiIdentity struct {
    SSID       string              `json:"ssid"`                  // required
    SSIDShared bool                `json:"ssid_shared,omitempty"` // false = exclusive (default)
    AuthModes  []WiFiAuthMode      `json:"auth_modes"`            // every mode the network advertises
    PMF        PMFMode             `json:"pmf,omitempty"`         // "", "optional", "required"
    Enterprise *EnterpriseIdentity `json:"enterprise,omitempty"`
}

type PMFMode string

type PortalDomainRole string // "primary" | "delegate" | "api"

type PortalDomain struct {
    Name                    string           `json:"name"`
    Role                    PortalDomainRole `json:"role"`
    PinnedSPKIHashes        []string         `json:"pinned_spki_sha256"`              // required, per domain
    CertificateFingerprints []string         `json:"certificate_sha256,omitempty"`
}

// PortalTLSIdentity describes the HTTPS identity of a captive portal. Normal
// Web PKI validation remains required even when pins are present.
type PortalTLSIdentity struct {
    Domains []PortalDomain `json:"domains"`
}

// WiFiAuthMode: open, owe, wpa2-personal, wpa3-personal, wpa2-enterprise,
//               wpa3-enterprise, wpa3-enterprise-192
type EnterpriseIdentity struct {
    Federation string      `json:"federation,omitempty"` // "eduroam", "govroam", ...; "" = closed network
    AAA        []AAADomain `json:"aaa"`                  // may be empty only for a federation-only site
}


type GeoCertificate struct {
    SchemaVersion int                `json:"schema_version"` // 3
    CertificateId string             `json:"certificate_id"`
    Subject       Subject            `json:"subject"`
    Critical      []string           `json:"critical,omitempty"`
    WiFi          WiFiIdentity       `json:"wifi"`
    Portal        *PortalTLSIdentity `json:"portal,omitempty"`
    Areas         []GeoCertArea      `json:"areas"`
    AreasAltitude [][2]float64       `json:"areas_altitude"`
    NotValidBefore string            `json:"not_valid_before,omitempty"`
    NotValidAfter  string            `json:"not_valid_after"`
    MarshaledCert  []byte            `json:"-"`
}

// Who the registration authority bound this claim to
type Subject struct {
    ID   string `json:"id"`             // stable registrant id, e.g. a verified domain
    Name string `json:"name,omitempty"` // display only, never trusted for matching
}


// One set of users and the servers that authenticate them.
type AAADomain struct {
    Realms     []string        `json:"realms,omitempty"` // "ethz.ch" exact, "*.ethz.ch" subrealms
    EAPMethods []EAPMethodSpec `json:"eap_methods,omitempty"`
    Servers    []AuthServer    `json:"servers"`
}

type EAPMethodSpec struct {
    Method EAPMethod `json:"method"`           // eap-tls, peap, ttls (open-ended)
    Phase2 []string  `json:"phase2,omitempty"` // mschapv2, pap, gtc, ...
}

type AuthServer struct {
    Names            []string `json:"names,omitempty"` // SAN dNSName, falling back to CN
    PinnedSPKIHashes []string `json:"pinned_spki_sha256,omitempty"` // leaf key
    CASPKIHashes     []string `json:"ca_spki_sha256,omitempty"`     // issuing / root CA key
    CACertificates   []string `json:"ca_certificates,omitempty"`    // the CA certificates themselves, base64 DER, for supplicants that pin a CA
}


// unmarshals a geo certificate
func UnmarshalGeoCertificate(marshaledCertificate []byte) (*GeoCertificate, error) {
	certificate := new(GeoCertificate)
	err := json.Unmarshal(marshaledCertificate, certificate)
	if err != nil {
		return nil, err
	}

	certificate.MarshaledCert = marshaledCertificate

	return certificate, nil
}

// returns the marshaled certificate
func (cert *GeoCertificate) Marshal() []byte {
	return cert.MarshaledCert
}

// returns a version of the certificate
func (cert *GeoCertificate) JSON() string {
	return string(cert.MarshaledCert)
}

// computes the hash of a geo cert
func (cert *GeoCertificate) Hash() SHA256Hash {
	return sha256.Sum256(cert.MarshaledCert)
}

// computes the SMT nodes for a given geo certificate and a relative grid suze 'fGrow'
func (cert *GeoCertificate) BitStrings(fGrow float64) ([]*bitstring.RawBitStringPair, error) {
	bitstrings := make([]*bitstring.RawBitStringPair, 0)

	for i, area := range cert.Areas {
		altitude := cert.AreasAltitude[i]
		altitudeMin := altitude[0]
		altitudeMax := altitude[1]

		loops, err := area.Loops()
		if err != nil {
			return nil, err
		}

		polygons := make([]bitstring.Geometry2D, len(loops))
		for i, loop := range loops {
			polygons[i] = &bitstring.S2Geometry2D{
				Loop: loop,
			}
		}

		bs, err := bitstring.ExtrudedPolygonsToBitStringPairs(polygons, altitudeMin, altitudeMax, fGrow)
		if err != nil {
			return nil, err
		}

		bitstrings = append(bitstrings, bs...)
	}

	return bitstrings, nil
}
