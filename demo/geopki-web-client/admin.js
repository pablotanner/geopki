const SESSION_STORAGE_KEY = "geopki_admin_key";

const state = {
  key: sessionStorage.getItem(SESSION_STORAGE_KEY) || "",
  offset: 0,
  limit: 50,
  total: 0,
};

const el = {
  keyInput: document.getElementById("admin-key"),
  connectButton: document.getElementById("connect-button"),
  forgetKeyButton: document.getElementById("forget-key-button"),
  authStatus: document.getElementById("auth-status"),
  tableSection: document.getElementById("table-section"),
  tableBody: document.getElementById("cert-table-body"),
  summary: document.getElementById("summary"),
  pageSizeSelect: document.getElementById("page-size"),
  refreshButton: document.getElementById("refresh-button"),
  prevPageButton: document.getElementById("prev-page"),
  nextPageButton: document.getElementById("next-page"),
  pageIndicator: document.getElementById("page-indicator"),

  newCertButton: document.getElementById("new-cert-button"),
  createSection: document.getElementById("create-section"),
  createForm: document.getElementById("create-form"),
  createCertId: document.getElementById("create-cert-id"),
  createNotValidAfter: document.getElementById("create-not-valid-after"),
  createAltitudeMin: document.getElementById("create-altitude-min"),
  createAltitudeMax: document.getElementById("create-altitude-max"),
  createSsid: document.getElementById("create-ssid"),
  createAuthModes: document.getElementById("create-auth-modes"),
  createEnterpriseFields: document.getElementById("create-enterprise-fields"),
  createEap: document.getElementById("create-eap"),
  createAuthServerNames: document.getElementById("create-auth-server-names"),
  createTrustedCaFingerprints: document.getElementById(
    "create-trusted-ca-fingerprints"
  ),
  createPortalDomains: document.getElementById("create-portal-domains"),
  addPortalDomainButton: document.getElementById("add-portal-domain-button"),
  createMap: document.getElementById("create-map"),
  clearAreaButton: document.getElementById("clear-area-button"),
  areaStatus: document.getElementById("area-status"),
  createReleaseImmediately: document.getElementById(
    "create-release-immediately"
  ),
  createSubmitButton: document.getElementById("create-submit-button"),
  createCancelButton: document.getElementById("create-cancel-button"),
  createStatus: document.getElementById("create-status"),
};

// state for the "draw a rectangle" area picker on the create form
const createMapState = {
  map: null,
  cornerMarker: null,
  rectangle: null,
  firstCorner: null,
};

function setAuthStatus(message, kind) {
  el.authStatus.textContent = message;
  el.authStatus.className = kind || "";
}

function apiUrl(path, params) {
  const url = new URL(path, location.origin);
  url.searchParams.set("key", state.key);
  for (const [k, v] of Object.entries(params || {})) {
    url.searchParams.set(k, v);
  }
  return url.toString();
}

async function fetchCertificateList() {
  const response = await fetch(
    apiUrl("/v1/admin/certificates", {
      limit: state.limit,
      offset: state.offset,
    })
  );

  if (response.status === 401) {
    throw new Error("Invalid insertion key");
  }

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `request failed with status ${response.status}`);
  }

  return response.json();
}

async function expireCertificates(hashes) {
  const response = await fetch(apiUrl("/v1/admin/expire"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hashes }),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `request failed with status ${response.status}`);
  }

  return response.json();
}

// gzip-compresses 'text' using the browser's native Compression Streams API.
// the server unconditionally gunzips the /v1/insert request body
// (see EndpointHandlerEnv.postInsert), so this is required, not optional.
async function gzipCompress(text) {
  if (typeof CompressionStream === "undefined") {
    throw new Error(
      "This browser doesn't support the Compression Streams API needed to " +
        "submit certificates. Try a recent Chrome, Edge, or Firefox."
    );
  }

  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Response(stream).arrayBuffer();
}

async function insertCertificates(certificates) {
  const compressedBody = await gzipCompress(JSON.stringify(certificates));

  const response = await fetch(apiUrl("/v1/insert"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: compressedBody,
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `insert failed with status ${response.status}`);
  }

  return response.json();
}

async function releaseNewVersion() {
  const response = await fetch(apiUrl("/v1/release"), { method: "POST" });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `release failed with status ${response.status}`);
  }

  return response.json();
}

function formatDate(isoString) {
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return isoString;
  return d.toLocaleString();
}

function textCell(value) {
  const td = document.createElement("td");
  td.textContent = value;
  return td;
}

// mean of a ring's vertices, skipping the closing point (ring[0] === ring[last]).
// good enough as a "definitely inside" query point for the rectangles this GUI
// draws; for a more exotic (e.g. non-convex) polygon it may land outside it.
function ringCentroid(ring) {
  let sumLng = 0;
  let sumLat = 0;
  const points = ring.slice(0, -1);

  for (const [lng, lat] of points) {
    sumLng += lng;
    sumLat += lat;
  }

  return [sumLng / points.length, sumLat / points.length];
}

// picks one lat/lng/altitude point that should hit the certificate's first
// area when used as the center of a query (with a small enough radius).
function representativeLocation(cert) {
  const area = cert.areas && cert.areas[0];
  const exteriorRing = area && area.coordinates && area.coordinates[0] && area.coordinates[0][0];
  if (!exteriorRing || exteriorRing.length === 0) return null;

  const [longitude, latitude] = ringCentroid(exteriorRing);

  const altitudeRange = cert.areas_altitude && cert.areas_altitude[0];
  const altitude = altitudeRange ? (altitudeRange[0] + altitudeRange[1]) / 2 : null;

  return {
    latitude,
    longitude,
    altitude,
    additionalAreas: (cert.areas || []).length - 1,
  };
}

function coordinatesCell(cert) {
  const td = document.createElement("td");
  td.className = "coordinates";

  const location = representativeLocation(cert);
  if (!location) {
    td.textContent = "-";
    return td;
  }

  const parts = [
    `lat ${location.latitude.toFixed(6)}`,
    `lon ${location.longitude.toFixed(6)}`,
  ];
  if (location.altitude !== null) {
    parts.push(`alt ${Math.round(location.altitude)}m`);
  }

  const code = document.createElement("code");
  code.textContent = parts.join(", ");
  td.appendChild(code);

  if (location.additionalAreas > 0) {
    const note = document.createElement("div");
    note.className = "coordinates-note";
    note.textContent = `+${location.additionalAreas} more area${
      location.additionalAreas > 1 ? "s" : ""
    } not shown`;
    td.appendChild(note);
  }

  return td;
}

function portalDomainsCell(cert) {
  const td = document.createElement("td");
  td.className = "portal-identity";
  const domains = (cert.portal && cert.portal.domains) || [];

  if (domains.length === 0) {
    td.textContent = "No portal domains";
    td.className += " muted";
    return td;
  }

  for (const domain of domains) {
    const item = document.createElement("div");
    item.className = "portal-domain";

    const name = document.createElement("strong");
    name.textContent = domain.name || "Unnamed domain";
    item.appendChild(name);

    if (domain.role) {
      const role = document.createElement("span");
      role.className = "domain-role";
      role.textContent = domain.role;
      item.appendChild(role);
    }

    const metadata = document.createElement("small");
    const spkiCount = (domain.pinned_spki_sha256 || []).length;
    const certCount = (domain.certificate_sha256 || []).length;
    const parts = [];
    if (spkiCount) parts.push(`${spkiCount} SPKI pin${spkiCount === 1 ? "" : "s"}`);
    if (certCount)
      parts.push(`${certCount} certificate fingerprint${certCount === 1 ? "" : "s"}`);
    metadata.textContent = parts.length ? parts.join(" · ") : "No pins configured";
    item.appendChild(metadata);
    td.appendChild(item);
  }

  return td;
}

function renderRow(entry) {
  const tr = document.createElement("tr");

  const cert = entry.certificate || {};
  const domains = (cert.portal && cert.portal.domains) || [];
  const ssid = (cert.wifi && cert.wifi.ssid) || "";

  // status
  const statusTd = document.createElement("td");
  const badge = document.createElement("span");
  badge.className = "badge " + (entry.expired ? "pending" : "active");
  badge.textContent = entry.expired ? "Pending removal" : "Active";
  statusTd.appendChild(badge);
  tr.appendChild(statusTd);

  tr.appendChild(textCell(cert.certificate_id || ""));
  tr.appendChild(portalDomainsCell(cert));
  tr.appendChild(textCell(ssid));
  tr.appendChild(textCell(formatDate(entry.not_valid_after)));
  tr.appendChild(coordinatesCell(cert));

  const hashTd = document.createElement("td");
  hashTd.className = "hash";
  const hashCode = document.createElement("code");
  hashCode.textContent = entry.hash;
  hashCode.title = entry.hash;
  hashTd.appendChild(hashCode);
  tr.appendChild(hashTd);

  const actionTd = document.createElement("td");
  if (!entry.expired) {
    const deleteButton = document.createElement("button");
    deleteButton.className = "danger";
    deleteButton.textContent = "Delete";
    deleteButton.addEventListener("click", () => onDeleteClicked(entry, deleteButton));
    actionTd.appendChild(deleteButton);
  }
  tr.appendChild(actionTd);

  return tr;
}

async function onDeleteClicked(entry, button) {
  const label = (entry.certificate && entry.certificate.certificate_id) || entry.hash;
  const confirmed = confirm(
    `Delete certificate "${label}"?\n\n` +
      "This marks it as expired immediately. It keeps showing up here as " +
      "'Pending removal' and still counts towards query results until an " +
      "operator triggers a release on the server."
  );
  if (!confirmed) return;

  button.disabled = true;
  button.textContent = "Deleting...";

  try {
    await expireCertificates([entry.hash]);
    await loadPage();
  } catch (e) {
    alert(`Failed to delete certificate: ${e.message}`);
    button.disabled = false;
    button.textContent = "Delete";
  }
}

async function loadPage() {
  el.summary.textContent = "Loading...";

  try {
    const data = await fetchCertificateList();
    state.total = data.total;

    el.tableBody.innerHTML = "";
    for (const entry of data.certificates) {
      el.tableBody.appendChild(renderRow(entry));
    }

    const from = data.total === 0 ? 0 : state.offset + 1;
    const to = Math.min(state.offset + data.certificates.length, data.total);
    el.summary.textContent = `Showing ${from}-${to} of ${data.total} certificates`;

    const totalPages = Math.max(1, Math.ceil(state.total / state.limit));
    const currentPage = Math.floor(state.offset / state.limit) + 1;
    el.pageIndicator.textContent = `Page ${currentPage} of ${totalPages}`;
    el.prevPageButton.disabled = state.offset <= 0;
    el.nextPageButton.disabled = state.offset + state.limit >= state.total;
  } catch (e) {
    el.summary.textContent = "";
    el.tableBody.innerHTML = "";
    alert(`Failed to load certificates: ${e.message}`);
  }
}

async function onConnect() {
  const key = el.keyInput.value.trim();
  if (!key) {
    setAuthStatus("Please enter an insertion key", "error");
    return;
  }

  state.key = key;
  state.offset = 0;

  setAuthStatus("Connecting...", "");

  try {
    // probe the key before revealing the table / persisting it
    await fetchCertificateList();

    sessionStorage.setItem(SESSION_STORAGE_KEY, key);
    setAuthStatus("Connected", "ok");
    el.tableSection.hidden = false;

    await loadPage();
  } catch (e) {
    setAuthStatus(e.message, "error");
    el.tableSection.hidden = true;
  }
}

function onForgetKey() {
  sessionStorage.removeItem(SESSION_STORAGE_KEY);
  state.key = "";
  el.keyInput.value = "";
  el.tableSection.hidden = true;
  el.createSection.hidden = true;
  setAuthStatus("Key forgotten", "");
}

// --- create certificate form ---

function initCreateMapIfNeeded() {
  if (createMapState.map) return;

  // roughly centered on the sample data used throughout SETUP.md
  createMapState.map = L.map(el.createMap).setView([47.3769, 8.5417], 15);

  L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 19,
    attribution: "© OpenStreetMap",
  }).addTo(createMapState.map);

  createMapState.map.on("click", onCreateMapClick);
}

function clearArea() {
  if (createMapState.cornerMarker) {
    createMapState.cornerMarker.remove();
    createMapState.cornerMarker = null;
  }
  if (createMapState.rectangle) {
    createMapState.rectangle.remove();
    createMapState.rectangle = null;
  }
  createMapState.firstCorner = null;
  el.areaStatus.textContent = "No area set";
  el.areaStatus.className = "";
}

function onCreateMapClick(e) {
  if (!createMapState.firstCorner) {
    // starting a new rectangle: drop the previous one, if any
    if (createMapState.rectangle) {
      createMapState.rectangle.remove();
      createMapState.rectangle = null;
    }
    createMapState.firstCorner = e.latlng;
    createMapState.cornerMarker = L.marker(e.latlng).addTo(createMapState.map);
    el.areaStatus.textContent = "Click the opposite corner...";
    el.areaStatus.className = "";
    return;
  }

  const bounds = L.latLngBounds(createMapState.firstCorner, e.latlng);
  createMapState.rectangle = L.rectangle(bounds, { color: "#1a7f37" }).addTo(
    createMapState.map
  );

  createMapState.cornerMarker.remove();
  createMapState.cornerMarker = null;
  createMapState.firstCorner = null;

  const sw = bounds.getSouthWest();
  const ne = bounds.getNorthEast();
  el.areaStatus.textContent = `Area set: (${sw.lat.toFixed(5)}, ${sw.lng.toFixed(
    5
  )}) to (${ne.lat.toFixed(5)}, ${ne.lng.toFixed(5)})`;
  el.areaStatus.className = "set";
}

// builds the GeoCertArea (see pkg/crypto/certificate.go) for the drawn rectangle
function areaFromRectangle() {
  if (!createMapState.rectangle) return null;

  const bounds = createMapState.rectangle.getBounds();
  const sw = bounds.getSouthWest();
  const ne = bounds.getNorthEast();

  // GeoJSON is [longitude, latitude]; ring must be closed and (for this simple
  // rectangle) is traced counterclockwise: SW -> SE -> NE -> NW -> SW
  const ring = [
    [sw.lng, sw.lat],
    [ne.lng, sw.lat],
    [ne.lng, ne.lat],
    [sw.lng, ne.lat],
    [sw.lng, sw.lat],
  ];

  return {
    type: "MultiPolygon",
    coordinates: [[ring], []],
  };
}

function splitCommaList(value) {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function addPortalDomainRow(values = {}) {
  const row = document.createElement("div");
  row.className = "portal-domain-row";
  row.innerHTML = `
    <div class="portal-domain-row-heading">
      <strong>Portal domain</strong>
      <button type="button" class="remove-portal-domain">Remove</button>
    </div>
    <label>Hostname <input type="text" class="portal-domain-name" placeholder="portal.example.com"></label>
    <label>Role
      <select class="portal-domain-role">
        <option value="primary">primary</option>
        <option value="delegate">delegate</option>
        <option value="api">api</option>
      </select>
    </label>
    <label>Pinned SPKI SHA-256 (comma separated)
      <input type="text" class="portal-domain-spki">
    </label>
    <label>Certificate SHA-256 (comma separated)
      <input type="text" class="portal-domain-cert-fp">
    </label>`;

  row.querySelector(".portal-domain-name").value = values.name || "";
  row.querySelector(".portal-domain-role").value = values.role || "primary";
  row.querySelector(".portal-domain-spki").value = (values.pinned_spki_sha256 || []).join(", ");
  row.querySelector(".portal-domain-cert-fp").value = (values.certificate_sha256 || []).join(", ");
  row.querySelector(".remove-portal-domain").addEventListener("click", () => {
    row.remove();
    updatePortalDomainControls();
  });
  el.createPortalDomains.appendChild(row);
  updatePortalDomainControls();
}

function updatePortalDomainControls() {
  const rows = el.createPortalDomains.querySelectorAll(".portal-domain-row");
  for (const row of rows) {
    row.querySelector(".remove-portal-domain").disabled = rows.length === 1;
  }
}

function setCreateStatus(message, kind) {
  el.createStatus.textContent = message;
  el.createStatus.className = kind || "";
}

function resetCreateForm() {
  el.createForm.reset();
  el.createEnterpriseFields.hidden = true;
  el.createPortalDomains.innerHTML = "";
  addPortalDomainRow();
  clearArea();
  setCreateStatus("", "");
}

function showCreateSection() {
  el.createSection.hidden = false;
  initCreateMapIfNeeded();
  // Leaflet needs a visible container to size itself correctly
  setTimeout(() => createMapState.map.invalidateSize(), 0);
}

function hideCreateSection() {
  el.createSection.hidden = true;
}

function buildCertificateFromForm() {
  const area = areaFromRectangle();
  if (!area) {
    throw new Error("Please draw a coverage area on the map first.");
  }

  const altitudeMin = parseFloat(el.createAltitudeMin.value);
  const altitudeMax = parseFloat(el.createAltitudeMax.value);
  if (isNaN(altitudeMin) || isNaN(altitudeMax) || altitudeMin > altitudeMax) {
    throw new Error("Min altitude must be a number and not exceed max altitude.");
  }

  if (!el.createNotValidAfter.value) {
    throw new Error("Please set a 'not valid after' date.");
  }
  const notValidAfter = new Date(el.createNotValidAfter.value).toISOString();

  const authMode = el.createAuthMode.value;
  const isEnterprise = authMode.endsWith("-enterprise");

  const wifi = { auth_mode: authMode };
  if (el.createSsid.value.trim()) wifi.ssid = el.createSsid.value.trim();
  if (isEnterprise) {
    wifi.eap = el.createEap.value;
    const authServerNames = splitCommaList(el.createAuthServerNames.value);
    if (authServerNames.length) wifi.auth_server_names = authServerNames;
    const trustedCaFingerprints = splitCommaList(
      el.createTrustedCaFingerprints.value
    );
    if (trustedCaFingerprints.length)
      wifi.trusted_ca_fingerprints = trustedCaFingerprints;
  }

  const portal = { domains: [] };
  for (const row of el.createPortalDomains.querySelectorAll(".portal-domain-row")) {
    const name = row.querySelector(".portal-domain-name").value.trim();
    const pinnedSpki = splitCommaList(row.querySelector(".portal-domain-spki").value);
    const certificateFingerprints = splitCommaList(
      row.querySelector(".portal-domain-cert-fp").value
    );
    if (!name) {
      if (pinnedSpki.length || certificateFingerprints.length) {
        throw new Error("Every portal pin must belong to a named domain.");
      }
      continue;
    }
    if (!pinnedSpki.length) {
      throw new Error(`Add at least one SPKI pin for ${name}.`);
    }
    portal.domains.push({
      name,
      role: row.querySelector(".portal-domain-role").value,
      pinned_spki_sha256: pinnedSpki,
      certificate_sha256: certificateFingerprints,
    });
  }

  const certId = el.createCertId.value.trim();
  if (!certId) {
    throw new Error("Please set a certificate ID.");
  }

  return {
    certificate_id: certId,
    wifi,
    portal,
    areas: [area],
    areas_altitude: [[altitudeMin, altitudeMax]],
    not_valid_after: notValidAfter,
  };
}

async function onCreateFormSubmit(e) {
  e.preventDefault();

  let certificate;
  try {
    certificate = buildCertificateFromForm();
  } catch (err) {
    setCreateStatus(err.message, "error");
    return;
  }

  el.createSubmitButton.disabled = true;
  el.createSubmitButton.textContent = "Creating...";
  setCreateStatus("Inserting certificate...", "");

  try {
    await insertCertificates([certificate]);

    if (el.createReleaseImmediately.checked) {
      setCreateStatus(
        "Certificate inserted, releasing new version (this can take a " +
          "while on a large dataset)...",
        ""
      );
      await releaseNewVersion();
      setCreateStatus("Certificate created and released.", "ok");
    } else {
      setCreateStatus(
        "Certificate inserted, but staged only -- it won't be queryable " +
          "or show up as 'Active' below until a release is triggered.",
        "ok"
      );
    }

    resetCreateForm();
    await loadPage();
  } catch (err) {
    setCreateStatus(`Failed: ${err.message}`, "error");
  } finally {
    el.createSubmitButton.disabled = false;
    el.createSubmitButton.textContent = "Create certificate";
  }
}

el.newCertButton.addEventListener("click", showCreateSection);
el.createCancelButton.addEventListener("click", () => {
  resetCreateForm();
  hideCreateSection();
});
el.clearAreaButton.addEventListener("click", clearArea);
el.addPortalDomainButton.addEventListener("click", () => addPortalDomainRow());
el.createForm.addEventListener("submit", onCreateFormSubmit);
el.createAuthModes.addEventListener("change", () => {
  const hasEnterpriseMode = Array.from(el.createAuthModes.selectedOptions).some(
    (option) => option.value.endsWith("-enterprise")
  );
  el.createEnterpriseFields.hidden = !hasEnterpriseMode;
});

el.connectButton.addEventListener("click", onConnect);
el.forgetKeyButton.addEventListener("click", onForgetKey);
el.keyInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") onConnect();
});

el.refreshButton.addEventListener("click", loadPage);

el.pageSizeSelect.addEventListener("change", () => {
  state.limit = parseInt(el.pageSizeSelect.value, 10);
  state.offset = 0;
  loadPage();
});

el.prevPageButton.addEventListener("click", () => {
  state.offset = Math.max(0, state.offset - state.limit);
  loadPage();
});

el.nextPageButton.addEventListener("click", () => {
  state.offset = state.offset + state.limit;
  loadPage();
});

// auto-connect if a key is already stored for this tab
if (state.key) {
  el.keyInput.value = state.key;
  onConnect();
}

addPortalDomainRow();
