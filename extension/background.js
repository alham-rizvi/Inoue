const extensionApi = globalThis.browser || globalThis.chrome;
const DEFAULT_API_URL = "http://127.0.0.1:8000";

function isWebUrl(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

function normalizeApiUrl(value) {
  const candidate = String(value || DEFAULT_API_URL).trim().replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(candidate)) {
    return DEFAULT_API_URL;
  }
  return candidate;
}

async function scanActiveTab() {
  const tabs = await extensionApi.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab || !isWebUrl(tab.url)) {
    return { ok: false, error: "Open an HTTP or HTTPS page before scanning." };
  }

  const settings = await extensionApi.storage.local.get({
    apiUrl: DEFAULT_API_URL,
    apiKey: ""
  });
  const endpoint = `${normalizeApiUrl(settings.apiUrl)}/scan`;
  const headers = { "Content-Type": "application/json" };
  if (settings.apiKey) {
    headers["X-API-Key"] = settings.apiKey;
  }

  let response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({
        target: tab.url,
        timeout: 10,
        follow_redirects: true,
        modules: ["fast"]
      })
    });
  } catch (error) {
    return { ok: false, error: `Could not reach Inoue API at ${endpoint}.` };
  }

  let payload = {};
  try {
    payload = await response.json();
  } catch (error) {
    return { ok: false, error: `Inoue API returned an invalid response (${response.status}).` };
  }
  if (!response.ok) {
    return { ok: false, error: payload.detail || `Inoue API returned HTTP ${response.status}.` };
  }
  if (payload.error) {
    return { ok: false, error: payload.error, data: payload };
  }
  return { ok: true, data: payload };
}

extensionApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "scan-active-tab") {
    return false;
  }
  scanActiveTab()
    .then(sendResponse)
    .catch((error) => sendResponse({ ok: false, error: error.message || "Scan failed." }));
  return true;
});
