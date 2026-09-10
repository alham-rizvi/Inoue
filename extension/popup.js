const extensionApi = globalThis.browser || globalThis.chrome;
const DEFAULT_API_URL = "http://127.0.0.1:8000";

const elements = {
  target: document.getElementById("target"),
  scan: document.getElementById("scan"),
  save: document.getElementById("save"),
  status: document.getElementById("status"),
  results: document.getElementById("results"),
  scanMeta: document.getElementById("scan-meta"),
  connection: document.getElementById("connection"),
  apiUrl: document.getElementById("api-url"),
  apiKey: document.getElementById("api-key")
};

function setStatus(message, isError = false) {
  elements.status.textContent = message;
  elements.status.classList.toggle("error", isError);
}

function renderResults(data) {
  elements.results.replaceChildren();
  const technologies = Array.isArray(data.technologies) ? data.technologies : [];
  if (!technologies.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "No recognizable technologies exposed by this page.";
    elements.results.append(empty);
    return;
  }
  technologies.forEach((technology) => {
    const card = document.createElement("article");
    card.className = "card";
    const top = document.createElement("div");
    top.className = "card-top";
    const name = document.createElement("strong");
    name.className = "name";
    name.textContent = technology.name || "Unknown";
    const version = document.createElement("span");
    version.className = "version";
    version.textContent = technology.version || "unknown";
    top.append(name, version);
    const category = document.createElement("div");
    category.className = "category";
    category.textContent = `${technology.category || "Other"} · ${technology.confidence || "unknown"} confidence`;
    card.append(top, category);
    if (typeof technology.confidence_score === "number") {
      const score = document.createElement("div");
      score.className = "score";
      score.textContent = `Signal score ${technology.confidence_score.toFixed(1)} / 100`;
      card.append(score);
    }
    if (Array.isArray(technology.cves) && technology.cves.length) {
      const cves = document.createElement("div");
      cves.className = "cves";
      cves.textContent = technology.cves.map((cve) => `${cve.id} · ${cve.severity || "unknown"}`).join(" | ");
      card.append(cves);
    }
    if (technology.evidence) {
      const evidence = document.createElement("span");
      evidence.className = "evidence";
      evidence.textContent = technology.evidence;
      card.append(evidence);
    }
    elements.results.append(card);
  });
}

function renderScanMeta(data) {
  elements.scanMeta.replaceChildren();
  elements.scanMeta.hidden = false;
  const values = [
    data.status_code ? `HTTP ${data.status_code}` : "HTTP unknown",
    data.server ? `Server ${data.server}` : "",
    data.ip ? `IP ${data.ip}` : "",
    data.final_url && data.final_url !== data.url ? "redirected" : ""
  ].filter(Boolean);
  elements.scanMeta.textContent = values.join(" · ");
}

async function requestApiPermission(apiUrl) {
  if (!extensionApi.permissions?.request) {
    return true;
  }
  const parsed = new URL(apiUrl);
  if (!/^https?:$/.test(parsed.protocol)) {
    return false;
  }
  return extensionApi.permissions.request({ origins: [`${parsed.protocol}//${parsed.host}/*`] });
}

async function loadSettings() {
  const settings = await extensionApi.storage.local.get({ apiUrl: DEFAULT_API_URL, apiKey: "" });
  elements.apiUrl.value = settings.apiUrl;
  elements.apiKey.value = settings.apiKey;
}

async function loadActiveTab() {
  const tabs = await extensionApi.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  elements.target.textContent = tab && tab.url ? tab.url : "No active tab";
}

async function scan() {
  elements.scan.disabled = true;
  elements.connection.classList.remove("ready");
  elements.results.replaceChildren();
  setStatus("Scanning active tab...");
  const response = await extensionApi.runtime.sendMessage({ type: "scan-active-tab" });
  elements.scan.disabled = false;
  if (!response || !response.ok) {
    setStatus(response?.error || "Scan failed.", true);
    return;
  }
  elements.connection.classList.add("ready");
  setStatus(`${response.data.technologies?.length || 0} technologies detected.`);
  renderScanMeta(response.data);
  renderResults(response.data);
}

elements.save.addEventListener("click", async () => {
  const apiUrl = elements.apiUrl.value.trim() || DEFAULT_API_URL;
  try {
    if (!(await requestApiPermission(apiUrl))) {
      setStatus("Browser permission for this API was not granted.", true);
      return;
    }
  } catch (error) {
    setStatus("Enter a valid HTTP or HTTPS API URL.", true);
    return;
  }
  await extensionApi.storage.local.set({ apiUrl, apiKey: elements.apiKey.value.trim() });
  setStatus("Settings saved.");
});
elements.scan.addEventListener("click", () => scan().catch((error) => setStatus(error.message, true)));

Promise.all([loadSettings(), loadActiveTab()]).catch((error) => setStatus(error.message, true));
