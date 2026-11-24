const siteEl = document.getElementById("site");
const resultEl = document.getElementById("result");
const scanButton = document.getElementById("scan");

let activeTab = null;

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  activeTab = tabs && tabs[0] ? tabs[0] : null;
  siteEl.textContent = activeTab?.url || "No active tab";
});

scanButton.addEventListener("click", async () => {
  if (!activeTab?.url || !/^https?:/.test(activeTab.url)) {
    resultEl.textContent = "Only ordinary HTTP/HTTPS pages can be scanned.";
    return;
  }

  resultEl.textContent =
    "Raw-page scanning is not enabled yet. The exact URL and HTML feature extractors from the training notebook must first be ported and parity-tested.";
});
