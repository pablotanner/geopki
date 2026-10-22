package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"geopki/pkg/comm"
	"geopki/pkg/crypto"
	"geopki/pkg/geometry"
)

const (
	// the relative grid size used to compute bit strings based on the query volume
	F_GROW = 1
)

func convertWiFiAuthModesToStrings (authModes []crypto.WiFiAuthMode) []string {
	strs := make([]string, len(authModes))
	for i, authMode := range authModes {
		strs[i] = string(authMode)
	}
	return strs
}

func main() {
	// CLI arguments described in the help messages below
	var address string
	var longitude, latitude, altitude float64
	var radius uint64
	var includeCertificates bool

	var publicKeyBase64 string

	flag.StringVar(&address, "address", "", "The HTTP address of the server to send the request to")
	flag.Float64Var(&longitude, "longitude", 190, "The longitude to query for")
	flag.Float64Var(&latitude, "latitude", 100, "The latitude to query for")
	flag.Float64Var(&altitude, "altitude", math.Inf(0), "The altitude to query for")
	flag.Uint64Var(&radius, "radius", 10, "The radius for the query in meters")
	flag.BoolVar(&includeCertificates, "include-certificates", false, "Whether to include the certificates")
	flag.StringVar(&publicKeyBase64, "public-key", "", "The public key used to verify the signatures.")
	flag.Parse()

	var publicKey *ecdsa.PublicKey

	// set up timing variables
	// shared start time for measuring durations
	var start time.Time

	// time for fetching and decoding the public key
	var fetchingDecodingPublicKey time.Duration

	// time for computing the query bit strings
	var buildingQuery time.Duration

	// time for sending a request and receiving a response
	var request time.Duration

	// time for locally verifying the response
	var verification time.Duration

	// time for locally verifiying the consistency
	var consistency time.Duration

	// start measuring 'fetchingDecodingPublicKey'
	start = time.Now()

	if len(publicKeyBase64) == 0 {
		fmt.Println("🚨 No public key passed as an argument, fetching it from the server.")

		plainResponse, err := http.Get(
			fmt.Sprintf("%s/v1/public-key", address),
		)
		if err != nil {
			log.Fatalf(
				"❌ failed sending HTTP GET request to %s: %v",
				address,
				err,
			)
		}

		defer plainResponse.Body.Close()

		responseBody, err := io.ReadAll(plainResponse.Body)
		if err != nil {
			log.Fatalf(
				"❌ failed reading response: %v",
				err,
			)
		}

		decodedPublicKey, err := x509.ParsePKIXPublicKey(responseBody)
		if err != nil {
			log.Fatalf(
				"❌ failed parsing public key: %v",
				err,
			)
		}

		// type assertion, crashes if the type does not match
		publicKey = decodedPublicKey.(*ecdsa.PublicKey)
	} else {
		// if a public key was passed as a CLI argument, decode it
		derPublicKey, err := base64.StdEncoding.DecodeString(publicKeyBase64)
		if err != nil {
			log.Fatalf(
				"❌ failed parsing base64 of public key flag: %v",
				err,
			)
		}

		// and parse the decoded data
		decodedPublicKey, err := x509.ParsePKIXPublicKey(derPublicKey)
		if err != nil {
			log.Fatalf(
				"❌ failed parsing public key: %v",
				err,
			)
		}

		// type assertion, crashes if the type does not match
		publicKey = decodedPublicKey.(*ecdsa.PublicKey)
	}

	// finish 'fetchingDecodingPublicKey' measurement
	fetchingDecodingPublicKey = time.Since(start)
	// start measuring 'buildingQuery'
	start = time.Now()

	// compute the query based on the input coordinates, radius and the relative grid size
	query, err := comm.NewQuery(longitude, latitude, altitude, radius, F_GROW, &geometry.GdalCircleApproximator{})
	if err != nil {
		log.Fatalf("❌ building query: %v\n", err)
	}

	// finish 'buildingQuery' measurement
	buildingQuery = time.Since(start)
	// start measuring 'request'
	start = time.Now()

	response, requestSize, responseSize, err := comm.QueryMapServer(
		address,
		query,
		includeCertificates,
	)
	if err != nil {
		log.Fatalf("❌ request failed: %v\n", err)
	}

	// finish 'request' measurement
	request = time.Since(start)
	// start measuring 'verification'
	start = time.Now()

	// ensure the response is complete with respect to the query and
	// that the server included exactly all data it knows in that area by
	// recomputing the root hash
	certificateHashes, err := crypto.VerifyResponse(response, query, publicKey)
	if err != nil {
		log.Fatalf("❌ response verification failed: %v\n", err)
	}

	// finish 'verification' measurement
	verification = time.Since(start)
	// start measuring 'consistency'
	start = time.Now()

	// ensure the received signed map head is included in the consistency tree
	// by requesting a proof of inclusion for the consistency tree
	err = crypto.EnsureConsistency(response, publicKey)
	if err != nil {
		log.Fatalf("❌ consistency verification failed: %v\n", err)
	}

	// finish 'consistency' measurement
	consistency = time.Since(start)

	fmt.Printf("✅ Cryptographic verification of response succeeded!\n")

	fmt.Printf("🏋️ Sizes\n")
	fmt.Printf("    Request size: %dB, %d bit strings\n", requestSize, len(query.XYBitStrings))
	fmt.Printf("    Response size: %dB, %d nodes\n", responseSize, len(response.Nodes))
	fmt.Printf("    Consistency proof response size: %dB\n", len(response.InclusionProof))

	fmt.Printf("⌛️ Timing\n")
	fmt.Printf("    Fetch & Parse Public Key: %fs\n", fetchingDecodingPublicKey.Seconds())
	fmt.Printf("    Build Query: %fs\n", buildingQuery.Seconds())
	fmt.Printf("    Send Request & Receive Response: %fs\n", request.Seconds())
	fmt.Printf("    Verify Response: %fs\n", verification.Seconds())
	fmt.Printf("    Verify Consistency: %fs\n", consistency.Seconds())

	fmt.Printf("📡 Received %d certificate hashes:\n", certificateHashes.Cardinality())
	for certificateHash := range certificateHashes.Iter() {
		fmt.Printf("    %s\n", certificateHash)
	}

	fmt.Printf("📡 Received %d certificates\n", len(response.GetCertificates()))

	// Parse and display the certificate policy in separate Wi-Fi and portal sections.
	for _, rawCertificate := range response.GetCertificates() {
		certificate, err := crypto.UnmarshalGeoCertificate(rawCertificate)
		if err != nil {
			log.Fatalf("❌ failed parsing certificate: %v\n", err)
		}

		fmt.Printf("\n    Certificate %s\n", certificate.CertificateId)
		fmt.Printf("      Valid until: %s\n", certificate.NotValidAfter)

		fmt.Printf("      Wi-Fi\n")
		if len(certificate.WiFi.AuthModes) > 0 {
			// multiple objects of type WiFiAuthMode are allowed in the AuthModes field, but only one is allowed in the AuthMode field.
			//fmt.Printf("        Authentication modes: %s\n", strings.Join(certificate.WiFi.AuthModes, ", "))
			// fix:  cannot use certificate.WiFi.AuthModes (variable of type []"geopki/pkg/crypto".WiFiAuthMode) as []string value in argument to strings.Join
			fmt.Printf("        Authentication modes: %s\n", strings.Join(convertWiFiAuthModesToStrings(certificate.WiFi.AuthModes), ", "))
		}
		if certificate.WiFi.SSID != "" {
			shared := "exclusive"
			if certificate.WiFi.SSIDShared {
				shared = "shared"
			}
			fmt.Printf("        SSID (%s): %s\n", shared, certificate.WiFi.SSID)
		}
		if len(certificate.Portal.Domains) > 0 {
			fmt.Printf("      Captive portal\n")
			for _, domain := range certificate.Portal.Domains {
				fmt.Printf("        Domain: %s (role: %s)\n", domain.Name, domain.Role)
				if len(domain.PinnedSPKIHashes) > 0 {
					fmt.Printf("          Pinned SPKI SHA-256: %s\n", strings.Join(domain.PinnedSPKIHashes, ", "))
				}
			if len(domain.CertificateFingerprints) > 0 {
					fmt.Printf("          Certificate SHA-256: %s\n", strings.Join(domain.CertificateFingerprints, ", "))
				}
			}
		}
	}
}
