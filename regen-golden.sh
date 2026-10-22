#!/usr/bin/env bash
# Wipes the GeoPKI DB, seeds a fixed set of test GeoCerts, releases,
# and dumps golden vectors for the Android port.
#
# Run from anywhere inside the geopki repo, with the server running:
#   DATABASE_URL=... CERT_INSERT_KEY=... ./regen-golden.sh --yes
# Optional: ADDR (default http://127.0.0.1:1234), ANDROID_TEST_RES (copy target)
set -euo pipefail

: "${DATABASE_URL:?set DATABASE_URL (same as the server)}"
: "${CERT_INSERT_KEY:?set CERT_INSERT_KEY (same as the server)}"
ADDR="${ADDR:-http://127.0.0.1:1234}"

if [[ "${1:-}" != "--yes" ]]; then
  echo "This TRUNCATEs certificates, nodes, nodes_next in \$DATABASE_URL. Re-run with --yes." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"
OUT=golden-out
mkdir -p "$OUT"

echo "==> wiping tables"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -c "TRUNCATE certificates, nodes, nodes_next;"

echo "==> generating fixtures"
python3 - "$OUT" <<'PY'
import json, math, sys
out = sys.argv[1]

def square(lon, lat, side_m):
    """Closed CCW square ring centred on (lon, lat), [lon, lat] order."""
    h = side_m / 2
    dlat = h / 111_320
    dlon = h / (111_320 * math.cos(math.radians(lat)))
    w, e, s, n = lon - dlon, lon + dlon, lat - dlat, lat + dlat
    return [[w, s], [e, s], [e, n], [w, n], [w, s]]

def area(lon, lat, side_m):
    return {"type": "MultiPolygon", "coordinates": [[square(lon, lat, side_m)], []]}

def cert(cid, domain, areas, alts):
    return {"certificate_id": cid, "domain": domain,
            "areas": areas, "areas_altitude": alts,
            "not_valid_after": "2030-01-01T00:00:00Z"}

ETH_A = (8.54900, 47.37860)
ETH_B = (8.54915, 47.37870)   # overlaps ETH_A
HB    = (8.54020, 47.37790)
STACK = (8.54460, 47.41160)   # same footprint, two floors
UETLI = (8.49180, 47.34970)
BUERK = (8.54130, 47.36670)

certs = [
    # overlap: one query returns several hashes
    cert("eth-a", "portal.eth-guest.test",   [area(*ETH_A, 30)], [[450, 500]]),
    cert("eth-b", "portal.cafe-overlap.test", [area(*ETH_B, 30)], [[450, 500]]),
    # larger single area
    cert("hb", "portal.sbb-wifi.test", [area(*HB, 120)], [[390, 440]]),
    # altitude separation: exercises the z subtrees
    cert("stack-low",  "portal.floor1.test", [area(*STACK, 30)], [[430, 445]]),
    cert("stack-high", "portal.floor9.test", [area(*STACK, 30)], [[500, 515]]),
    # one cert, two disjoint areas with different altitudes
    cert("multi", "portal.multi-site.test",
         [area(*UETLI, 40), area(*BUERK, 40)], [[860, 880], [400, 420]]),
]

def pt(name, lonlat, alt, r):
    return {"name": name, "lon": lonlat[0], "lat": lonlat[1], "alt": alt, "radius": r}

points = [
    # hit certs (proof vectors with cert mutations)
    pt("eth-overlap", ((ETH_A[0]+ETH_B[0])/2, (ETH_A[1]+ETH_B[1])/2), 475, 20),
    pt("hb",          HB,    415, 50),
    pt("stack-low",   STACK, 437, 5),
    pt("stack-high",  STACK, 507, 5),
    pt("stack-both",  STACK, 470, 60),
    pt("multi-uetli", UETLI, 870, 20),
    pt("multi-buerk", BUERK, 410, 20),
    # empty area
    pt("empty",       (9.2, 46.1), 1500, 50),
    # encoder edge cases
    pt("radius-0",          ETH_A, 470, 0),
    pt("radius-max",        ETH_A, 470, 253),
    pt("antimeridian-east", (180, 0), 0, 20),
    pt("antimeridian-west", (-180, 0), 0, 20),
    pt("south-pole",        (0, -90), 2800, 20),
    pt("alt-min",           ETH_A, -11000, 10),
    pt("alt-max",           ETH_A, 32767 - 11000, 10),
    # must be rejected by the encoder
    pt("err-radius", ETH_A, 470, 254),
    pt("err-lon",    (180.0001, 0), 0, 10),
    pt("err-alt",    ETH_A, -11001, 10),
]

json.dump(certs,  open(f"{out}/certs.json",  "w"), indent=2)
json.dump(points, open(f"{out}/points.json", "w"), indent=2)
print(f"   {len(certs)} certs, {len(points)} points")
PY

echo "==> ingesting"
go run ./cmd/geopki-client-ingestion --address="$ADDR" \
  --insertion-key="$CERT_INSERT_KEY" --certificates="$OUT/certs.json"

echo "==> releasing (nodes_next -> nodes)"
go run ./cmd/release --address="$ADDR" --insertion-key="$CERT_INSERT_KEY"

echo "==> sanity check (expect >=2 hashes at the ETH overlap)"
SANITY=$(go run ./cmd/geopki-client --address="$ADDR" \
  --longitude=8.549075 --latitude=47.37865 --altitude=475 --radius=20 2>&1) || {
  echo "$SANITY"; echo "sanity query failed" >&2; exit 1; }
N=$(grep -oP 'Received \K[0-9]+(?= certificate hashes)' <<<"$SANITY" || echo 0)
if (( N < 2 )); then
  echo "$SANITY"
  echo "expected >=2 hashes, got $N (nodes_next workaround missing? altitude semantics?)" >&2
  exit 1
fi
echo "   ok, $N hashes"

echo "==> dumping golden vectors"
go run ./cmd/golden-dump -address "$ADDR" -points "$OUT/points.json" -out "$OUT/golden.json"

if [[ -n "${ANDROID_TEST_RES:-}" ]]; then
  cp "$OUT/golden.json" "$ANDROID_TEST_RES/golden.json"
  echo "==> copied to $ANDROID_TEST_RES"
fi
echo "done: $OUT/golden.json"