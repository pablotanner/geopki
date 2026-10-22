# GeoPKI local setup guide 

## Install prerequisites inside WSL2

Open your Ubuntu terminal (Windows Terminal → Ubuntu profile) and run:

```bash
sudo apt update
sudo apt install -y golang-go postgresql postgresql-contrib libgdal-dev git
go version  
```

---

## Clone the repo (inside WSL2)

```bash
mkdir -p ~/repos && cd ~/repos
git clone https://github.com/netsec-ethz/geopki.git
cd geopki
go mod download
```

---

## OPTIONAL: Reset Postgres DB
```bash
sudo -u postgres psql -c "DROP DATABASE geopki;"
sudo -u postgres psql -c "DROP USER pablo;"
```
---

## Set up the Postgres database

Start Postgres if it isn't running:

```bash
sudo service postgresql start
```

Create the user and database:

```bash
sudo -u postgres psql -c "CREATE USER pablo WITH PASSWORD '<password>';"
sudo -u postgres psql -c "CREATE DATABASE geopki OWNER pablo;"
```

SQL Functions
```bash
psql -U pablo -d geopki -f database/functions/min_altitude_of_bit_string.sql
psql -U pablo -d geopki -f database/functions/max_altitude_of_bit_string.sql
psql -U pablo -d geopki -f database/functions/array_difference.sql
psql -U pablo -d geopki -f database/functions/array_intersect.sql
psql -U pablo -d geopki -f database/functions/array_union.sql
psql -U pablo -d geopki -f database/functions/smt_hash.sql
psql -U pablo -d geopki -f database/functions/update_children_hashes.sql
```

Create the schema:  

```bash
psql -U pablo -d geopki -f database/tables/certificates.sql
psql -U pablo -d geopki -f database/tables/nodes.sql
```


---

## Set up Trillian 

```bash
cd ~/repos
git clone https://github.com/google/trillian.git
cd trillian
git checkout v1.5.2
```

### Optional: Reset Trillian
```bash
cd ~/Thesis/trillian/examples/deployment
docker compose down -v
```


### Trillian Local Deployment
```bash
cd ~/Thesis/trillian
export MYSQL_ROOT_PASSWORD="<see lab-secrets/geopki/SETUP-with-secrets-*>"
#export MYSQL_ROOT_PASSWORD="$(openssl rand -hex 16)"
docker-compose -f examples/deployment/docker-compose.yml up
```
Once Trillian's admin server is up on `127.0.0.1:8090`, create a new tree:

```bash
go run ./cmd/createtree --admin_server=127.0.0.1:8090
```

Log ID: 
5656256576233247638
---

## Configure environment variables (inside WSL2)

```bash
export GOTOOLCHAIN=go1.20.14
go version
```

```bash
export DATABASE_URL=postgresql://pablo:<password>@127.0.0.1:5432/geopki
export CERT_INSERT_KEY=<see lab-secrets/geopki/envrc-*>
```

```bash
export PRIVATE_KEY=<see lab-secrets/geopki/envrc-*>
```

---

## Run the server (inside WSL2)

```bash
export CGO_CFLAGS="$(go env CGO_CFLAGS) -Wno-deprecated-declarations"
```

```bash
go run ./cmd/geopki-server \
  --address=0.0.0.0 \
  --port=1234 \
  --trillian-address=127.0.0.1:8090 \
  --clog-id=5656256576233247638
```

A clean start means you have a live map server on `http://127.0.0.1:1234` inside WSL2.

---

## Registering a test GeoCert

Insertion is a **two-step process**: `/v1/insert` only stages data into a
`nodes_next` table; nothing is queryable until a separate `/v1/release` call
promotes it. Skipping the release step is the most common way to get an
"integrity check failed" or "root hash mismatch" error on a freshly-inserted
cert.

### 1. Insert

The repo ships a dedicated ingestion client, `cmd/geopki-client-ingestion`,
which POSTs JSON (gzip-compressed) to `/v1/insert`. The wire format is a plain
JSON array of `GeoCertificate` objects — no protobuf involved for this
endpoint (that's only used by `/query`). Schema, straight from
`pkg/crypto/certificate.go`:

Gotchas that will otherwise cost you time:
- **Coordinates are `[longitude, latitude]`**, GeoJSON order, not lat/lon.
- The ring **must close** (first point repeated as the last) and go
  **counterclockwise** — the server rejects malformed loops.
- `coordinates` is `[exteriorRings[], interiorRings[]]`; the empty `[]` for
  interior rings is required even when you have none (no holes in the
  polygon).
- `areas_altitude` has one `[min, max]` pair per entry in `areas`, in meters.
  Use a range that includes 0 to match ground-level queries.
- `not_valid_after` is inserted directly as a Postgres `timestamp with time
  zone` literal — ISO 8601 (`"2027-01-01T00:00:00Z"`) or the Postgres-native
  `"2027-01-01 00:00:00+00"` both work.
- Certificates can attach to intermediate nodes, not just leaves — you don't
  need to hit the deepest possible tree depth for a valid test cert.


```bash
cat > /tmp/mango-a.json <<'JSON'
[
  {
    "schema_version": 3,
    "certificate_id": "mango-a",
    "subject": { "id": "gecko-a.lab", "name": "GECKO Lab, Router A" },
    "critical": [],
    "wifi": {
      "ssid": "GeckoTest",
      "auth_modes": ["open"]
    },
    "portal": {
      "domains": [
        {
          "name": "portal.gecko-a.lab",
          "role": "primary",
          "pinned_spki_sha256": ["dAJnHfG0hpOWSRhQOeWz1NBoiXHnUnB2y/40h9i2exk="]
        },
        {
          "name": "pay.gecko-pay.lab",
          "role": "delegate",
          "pinned_spki_sha256": ["u9H7ovOnPGAi3ptBn2262bEEeXNcndvZCmnr8gmG3+c="]
        }
      ]
    },
    "areas": [{
      "type": "MultiPolygon",
      "coordinates": [[[[8.515,47.360],[8.565,47.360],[8.565,47.390],[8.515,47.390],[8.515,47.360]]],[]]
    }],
    "areas_altitude": [[200,700]],
    "not_valid_after": "2031-09-26T15:28:00Z"
  }
]
JSON
go run ./cmd/geopki-client-ingestion \
  --address=http://127.0.0.1:1234 \
  --insertion-key=$CERT_INSERT_KEY \
  --certificates=/tmp/mango-a.json

```

### 2. Release (required before querying)

```bash
curl -X POST "http://127.0.0.1:1234/v1/release?key=$CERT_INSERT_KEY"
```

This swaps `nodes_next` into the live `nodes` table and signs a new Map Head
with the real root hash. Watch the `geopki-server` terminal — it logs timing
for each stage (expired-cert cleanup, index rebuild, table swap, SMH/SCH
update), so a failure shows you exactly which stage broke. Success returns
`{"success":true, "new_tree_size":N}`.

### 3. Verify

```bash
go run ./cmd/geopki-client \
  --address=http://127.0.0.1:1234 \
  --longitude=8.5487 \
  --latitude=47.3769 \
  --altitude=400 \
  --radius=100 \
  --include-certificates
```

Should now return the cert instead of an integrity/hash error. If you insert
more certs later, repeat insert → release → query for each batch; release
only needs to run once per batch, not once per cert.

---

## Register your benign AP's test GeoCert

The server exposes `/v1/insert`, protected by `CERT_INSERT_KEY`, for inserting test data without needing the full OSM dataset.

The exact request format lives in `internal/geopki-server/ingestion.go` and `proto/request.proto` — worth reading both before attempting this, or asking Juan for a working example insert command, since guessing the wire format here risks wasted time. Once you can insert successfully, register a cert with coordinates matching wherever your benign AP physically sits.

---

## Reaching your WSL2 server from your physical phone

Your phone connects over WiFi; WSL2 traditionally sits behind a virtualized NAT, so `127.0.0.1` inside WSL2 isn't reachable from another device by default.

**Preferred: enable mirrored networking.** Create/edit `%UserProfile%\.wslconfig` on the Windows side:

```ini
[wsl2]
networkingMode=mirrored
```

Restart WSL2:

```powershell
wsl --shutdown
```

Reopen your Ubuntu terminal. With mirrored mode, WSL2 shares your Windows machine's real network identity — your phone can hit your laptop's normal LAN IP on port 1234 directly.

**Fallback, if mirrored mode isn't available** (older Windows/WSL2): in an elevated PowerShell:

```powershell
netsh interface portproxy add v4tov4 listenport=1234 listenaddress=0.0.0.0 connectport=1234 connectaddress=(wsl hostname -I)
```

Then allow port 1234 through Windows Firewall. Your phone connects to your Windows machine's LAN IP; Windows forwards the traffic into WSL2.

Either way, find your address to actually use:

```bash
hostname -I   # inside WSL2
```

or check `ipconfig` on the Windows side for your LAN IP. Use that address (not `127.0.0.1`) when pointing your Android app at the server.

---

## 13. Your two-AP experimental setup

- **Benign AP**: a router or `hostapd`-based setup running a captive portal, physically placed at the coordinates registered in step 11.
- **Attacker AP**: a second `hostapd` instance (or your Flipper Zero setup) broadcasting a similar/spoofed SSID and captive portal, with no registered GeoCert — or one registered at a mismatched location.
- **Your Android app** (built in Android Studio on Windows) connects to each in turn, queries your WSL2-hosted server via the LAN IP from step 12, and should show verified for the benign AP, warning for the attacker one.

**Concrete first milestone**: get step 10 (CLI client) fully working with a real registered cert before writing any Android code. That isolates "does the server/data model work" from "does my Android networking code work" — much easier to debug one thing at a time.


gzip -n -c admin.js > admin.js.fasthttp.gz
gzip -n -c admin.html > admin.html.fasthttp.gz
gzip -n -c admin.css > admin.css.fasthttp.gz
gzip -n -c demo.js > demo.js.fasthttp.gz