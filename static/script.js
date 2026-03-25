/* ── ELEMENTS ───────────────────────────────────────────────── */
const checkBtn        = document.getElementById("checkBtn");
const copyBtn         = document.getElementById("copyBtn");
const clearBtn        = document.getElementById("clearBtn");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");
const themeToggle     = document.getElementById("themeToggle");
const feedbackBtn     = document.getElementById("feedbackBtn");
const inputText       = document.getElementById("inputText");
const urlInput        = document.getElementById("urlInput");

const emptyState      = document.getElementById("emptyState");
const resultBox       = document.getElementById("result");
const scoreEl         = document.getElementById("score");
const verdictEl       = document.getElementById("verdict");
const explanationEl   = document.getElementById("explanation");
const badgeEl         = document.getElementById("badge");
const reasonsEl       = document.getElementById("reasons");
const adviceEl        = document.getElementById("advice");
const highlightedTextEl = document.getElementById("highlightedText");
const historyListEl   = document.getElementById("historyList");
const ringFill        = document.getElementById("ringFill");

const ratingModal   = document.getElementById("ratingModal");
const ratingClose   = document.getElementById("ratingClose");
const submitFeedback= document.getElementById("submitFeedback");

let lastResult     = null;
let selectedRating = 0;
let hasRated       = false;

/* ── THEME ──────────────────────────────────────────────────── */
function setTheme(isLight) {
  document.body.classList.toggle("light", isLight);
  themeToggle.textContent = isLight ? "🌙" : "☀";
  localStorage.setItem("fakecutTheme", isLight ? "light" : "dark");
}
themeToggle.addEventListener("click", () => setTheme(!document.body.classList.contains("light")));

/* ── HISTORY ────────────────────────────────────────────────── */
function getHistory() { return JSON.parse(localStorage.getItem("fakecutHistory") || "[]"); }
function saveHistory(item) {
  const h = getHistory(); h.unshift(item);
  localStorage.setItem("fakecutHistory", JSON.stringify(h.slice(0, 6)));
  renderHistory();
}
function renderHistory() {
  const h = getHistory();
  historyListEl.innerHTML = "";
  if (!h.length) { historyListEl.innerHTML = `<p class="note">No checks yet.</p>`; return; }
  h.forEach(item => {
    const d = document.createElement("div");
    d.className = "history-item";
    d.innerHTML = `<div class="hi-badge ${item.badge}">${item.verdict.toUpperCase()}</div>
      <h4>${item.score}/100</h4><p>${escapeHtml(item.preview)}</p>`;
    historyListEl.appendChild(d);
  });
}

/* ── TABS ───────────────────────────────────────────────────── */
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => { p.classList.add("hidden"); p.classList.remove("active"); });
    tab.classList.add("active");
    const panel = document.getElementById("tab-" + tab.dataset.tab);
    if (panel) { panel.classList.remove("hidden"); panel.classList.add("active"); }
  });
});

/* ── SCORE RING ─────────────────────────────────────────────── */
function animateRing(score, badgeClass) {
  const offset = 213.6 - (score / 100) * 213.6;
  ringFill.style.strokeDashoffset = offset;
  ringFill.className = "ring-fill " + badgeClass;
}

/* ── HIGHLIGHT ──────────────────────────────────────────────── */
function highlightText(text, words) {
  let out = escapeHtml(text);
  (words || []).forEach(w => {
    const safe = w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    out = out.replace(new RegExp(`(${safe})`, "gi"), "<mark>$1</mark>");
  });
  return out.replace(/\n/g, "<br>");
}

/* ── RENDER ─────────────────────────────────────────────────── */
function renderResult(data, text) {
  emptyState.classList.add("hidden");
  resultBox.classList.remove("hidden");

  scoreEl.textContent = data.score;
  verdictEl.textContent = data.verdict;
  explanationEl.textContent = data.explanation;
  badgeEl.textContent = data.verdict.toUpperCase();
  badgeEl.className = `badge ${data.badge}`;
  animateRing(data.score, data.badge);

  reasonsEl.innerHTML = "";
  (data.reasons || []).forEach(r => { const li = document.createElement("li"); li.textContent = r; reasonsEl.appendChild(li); });
  adviceEl.innerHTML = "";
  (data.advice || []).forEach(a => { const li = document.createElement("li"); li.textContent = a; adviceEl.appendChild(li); });

  highlightedTextEl.innerHTML = highlightText(text || "(No text provided)", data.matched_terms);
  lastResult = data;

  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(p => { p.classList.add("hidden"); p.classList.remove("active"); });
  document.querySelector('[data-tab="highlight"]').classList.add("active");
  document.getElementById("tab-highlight").classList.remove("hidden");
  document.getElementById("tab-highlight").classList.add("active");
}

/* ── CHECK ──────────────────────────────────────────────────── */
checkBtn.addEventListener("click", async () => {
  const text = inputText.value.trim();
  const url  = urlInput.value.trim();
  if (!text && !url) { alert("Paste some text or a URL to check."); return; }

  checkBtn.disabled = true;
  checkBtn.innerHTML = `<span>⏳</span> Analysing…`;

  try {
    const res  = await fetch("/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text, url }) });
    const data = await res.json();
    if (!res.ok) { alert(data.error || "Something went wrong."); return; }

    renderResult(data, text || url);
    saveHistory({ score: data.score, verdict: data.verdict, badge: data.badge, preview: (text || url).slice(0, 100) });

    if (!sessionStorage.getItem("fakecutChecked")) {
      sessionStorage.setItem("fakecutChecked", "1");
      setTimeout(() => showRatingModal(), 2400);
    }
  } catch (e) {
    alert("Could not connect to the server.");
    console.error(e);
  } finally {
    checkBtn.disabled = false;
    checkBtn.innerHTML = `<span>🔍</span> Analyse Now`;
  }
});

/* ── COPY ───────────────────────────────────────────────────── */
copyBtn.addEventListener("click", async () => {
  if (!lastResult) { alert("Run a check first."); return; }
  const txt = `FAKECUT Result\n\nVerdict: ${lastResult.verdict}\nScore: ${lastResult.score}/100\nExplanation: ${lastResult.explanation}\n\nReasons:\n${lastResult.reasons.map(r => "• " + r).join("\n")}`;
  try { await navigator.clipboard.writeText(txt); alert("Copied!"); } catch { alert("Copy failed."); }
});

/* ── CLEAR ──────────────────────────────────────────────────── */
clearBtn.addEventListener("click", () => {
  inputText.value = ""; urlInput.value = "";
  lastResult = null;
  resultBox.classList.add("hidden");
  emptyState.classList.remove("hidden");
  ringFill.style.strokeDashoffset = "213.6";
});
clearHistoryBtn.addEventListener("click", () => { localStorage.removeItem("fakecutHistory"); renderHistory(); });

/* ── RATING MODAL ───────────────────────────────────────────── */
function showRatingModal(force = false) {
  if (hasRated && !force) return;
  selectedRating = 0;
  document.querySelectorAll(".star").forEach(s => s.classList.remove("active", "hover"));
  ratingModal.classList.remove("hidden");
}
feedbackBtn.addEventListener("click", () => showRatingModal(true));
ratingClose.addEventListener("click", () => ratingModal.classList.add("hidden"));
ratingModal.addEventListener("click", e => { if (e.target === ratingModal) ratingModal.classList.add("hidden"); });

document.querySelectorAll(".star").forEach(star => {
  star.addEventListener("mouseenter", () => {
    const v = +star.dataset.v;
    document.querySelectorAll(".star").forEach(s => s.classList.toggle("hover", +s.dataset.v <= v));
  });
  star.addEventListener("mouseleave", () => document.querySelectorAll(".star").forEach(s => s.classList.remove("hover")));
  star.addEventListener("click", () => {
    selectedRating = +star.dataset.v;
    document.querySelectorAll(".star").forEach(s => s.classList.toggle("active", +s.dataset.v <= selectedRating));
  });
});

submitFeedback.addEventListener("click", async () => {
  if (!selectedRating) { alert("Please select a star rating."); return; }
  submitFeedback.disabled = true;
  submitFeedback.textContent = "Sending…";

  try {
    await fetch("/feedback", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ rating: `${selectedRating} / 5 stars` }) });
  } catch (e) { console.error(e); }

  hasRated = true;
  submitFeedback.textContent = "✓ Thank you!";
  setTimeout(() => ratingModal.classList.add("hidden"), 1400);
  submitFeedback.disabled = false;
});

/* ── HELPERS ────────────────────────────────────────────────── */
function escapeHtml(str) {
  return (str || "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;");
}

/* ── INIT ───────────────────────────────────────────────────── */
(function init() {
  const saved = localStorage.getItem("fakecutTheme") || "dark";
  setTheme(saved === "light");
  renderHistory();
})();
