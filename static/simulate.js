// ---------------- state ----------------
let simData = null;
let currentRound = 1;
let currentStrategy = "vulnerable"; // or "secure"
let playTimer = null;
let trendChart = null;

// ---------------- element refs ----------------
const runBtn = document.getElementById("runBtn");
const emptyState = document.getElementById("emptyState");
const resultsWrap = document.getElementById("resultsWrap");

const canvas = document.getElementById("graphCanvas");
const ctx = canvas.getContext("2d");

const roundSlider = document.getElementById("roundSlider");
const roundLabel = document.getElementById("roundLabel");
const prevBtn = document.getElementById("prevBtn");
const nextBtn = document.getElementById("nextBtn");
const playBtn = document.getElementById("playBtn");

const statusPill = document.getElementById("statusPill");
const statusDetail = document.getElementById("statusDetail");

const toggleBtns = document.querySelectorAll(".toggle-btn");

// ---------------- run simulation ----------------

runBtn.addEventListener("click", async () => {
  const payload = {
    num_honest: parseInt(document.getElementById("num_honest").value, 10),
    num_attackers: parseInt(document.getElementById("num_attackers").value, 10),
    rounds: parseInt(document.getElementById("rounds").value, 10),
    attacker_subnet_span: parseInt(document.getElementById("subnet_span").value, 10),
  };
  const seedVal = document.getElementById("seed").value;
  if (seedVal !== "") payload.seed = parseInt(seedVal, 10);

  runBtn.disabled = true;
  runBtn.textContent = "Running…";
  stopPlaying();

  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Simulation failed");
    }
    simData = await res.json();
    currentRound = 1;
    initResults();
  } catch (e) {
    alert("Error running simulation: " + e.message);
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "▶ Run Simulation";
  }
});

function initResults() {
  emptyState.classList.add("hidden");
  resultsWrap.classList.remove("hidden");

  document.getElementById("victimId").textContent = simData.victim_id;

  const vulnEclipsed = simData.history.filter(r => r.vulnerable.eclipsed).length;
  const secureEclipsed = simData.history.filter(r => r.secure.eclipsed).length;
  document.getElementById("vulnEclipsedCount").textContent = `${vulnEclipsed} / ${simData.history.length}`;
  document.getElementById("secureEclipsedCount").textContent = `${secureEclipsed} / ${simData.history.length}`;

  roundSlider.min = 1;
  roundSlider.max = simData.history.length;
  roundSlider.value = 1;

  renderTrendChart();
  renderRound();
}

// ---------------- strategy toggle ----------------

toggleBtns.forEach(btn => {
  btn.addEventListener("click", () => {
    toggleBtns.forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    currentStrategy = btn.dataset.strategy;
    renderRound();
  });
});

// ---------------- round controls ----------------

roundSlider.addEventListener("input", () => {
  currentRound = parseInt(roundSlider.value, 10);
  renderRound();
});

prevBtn.addEventListener("click", () => {
  stopPlaying();
  if (currentRound > 1) { currentRound--; syncSlider(); renderRound(); }
});

nextBtn.addEventListener("click", () => {
  stopPlaying();
  if (simData && currentRound < simData.history.length) { currentRound++; syncSlider(); renderRound(); }
});

playBtn.addEventListener("click", () => {
  if (playTimer) { stopPlaying(); return; }
  playBtn.textContent = "⏸ Pause";
  playTimer = setInterval(() => {
    if (!simData) return;
    if (currentRound >= simData.history.length) { currentRound = 1; }
    else { currentRound++; }
    syncSlider();
    renderRound();
  }, 1100);
});

function stopPlaying() {
  if (playTimer) { clearInterval(playTimer); playTimer = null; playBtn.textContent = "▶ Play"; }
}

function syncSlider() { roundSlider.value = currentRound; }

// ---------------- rendering ----------------

function renderRound() {
  if (!simData) return;
  const round = simData.history[currentRound - 1];
  const strategyData = round[currentStrategy];

  roundLabel.textContent = `Round ${currentRound} / ${simData.history.length}`;

  const eclipsed = strategyData.eclipsed;
  statusPill.textContent = eclipsed ? "ECLIPSED" : "SAFE";
  statusPill.className = "status-pill " + (eclipsed ? "eclipsed" : "safe");
  statusDetail.textContent = `${strategyData.malicious} / ${strategyData.total} malicious connections`;

  drawGraph(round.network, new Set(strategyData.selected_keys), simData.config.id_bits);
}

function hashKey(key) {
  // deterministic pseudo-random angle from an integer key
  let h = (key * 2654435761) % 2 ** 32;
  h = h ^ (h >>> 13);
  return (h % 360 + 360) % 360;
}

function drawGraph(network, selectedKeys, idBits) {
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const cx = w / 2, cy = h / 2;
  const maxRadius = Math.min(w, h) / 2 - 34;
  const maxBucket = idBits - 1;

  const cssVar = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const borderColor = cssVar("--border") || "#2a3350";
  const accent = cssVar("--accent") || "#5b8cff";
  const danger = cssVar("--danger") || "#ff5c7a";
  const success = cssVar("--success") || "#3ddc97";
  const warn = cssVar("--warn") || "#ffb454";
  const muted = cssVar("--muted") || "#8b93ab";

  // background bucket rings
  ctx.strokeStyle = borderColor;
  ctx.lineWidth = 1;
  for (let b = 0; b <= maxBucket; b += 1) {
    const r = 24 + (b / maxBucket) * (maxRadius - 24);
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.stroke();
  }
  ctx.fillStyle = muted;
  ctx.font = "10px sans-serif";
  ctx.fillText("close", cx + 6, cy - 20);
  ctx.fillText("far", cx + 6, cy - maxRadius + 4);

  // precompute positions
  const positions = new Map();
  network.forEach(p => {
    const bucket = p.bucket === null || p.bucket === undefined ? 0 : p.bucket;
    const r = 24 + (bucket / maxBucket) * (maxRadius - 24);
    const angleDeg = hashKey(p.key);
    const angle = (angleDeg * Math.PI) / 180;
    const x = cx + r * Math.cos(angle);
    const y = cy + r * Math.sin(angle);
    positions.set(p.key, { x, y });
  });

  // connection lines first (so dots render on top)
  network.forEach(p => {
    if (!selectedKeys.has(p.key)) return;
    const pos = positions.get(p.key);
    ctx.strokeStyle = p.malicious ? danger : success;
    ctx.globalAlpha = 0.85;
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(pos.x, pos.y);
    ctx.stroke();
  });
  ctx.globalAlpha = 1;

  // peer dots
  network.forEach(p => {
    const pos = positions.get(p.key);
    const selected = selectedKeys.has(p.key);
    const radius = selected ? 5.5 : 3.2;
    ctx.beginPath();
    ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
    ctx.fillStyle = p.malicious ? danger : accent;
    ctx.globalAlpha = selected ? 1 : 0.55;
    ctx.fill();
    if (selected) {
      ctx.lineWidth = 1.4;
      ctx.strokeStyle = "#ffffff";
      ctx.globalAlpha = 0.9;
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
  });

  // victim node
  ctx.beginPath();
  ctx.arc(cx, cy, 9, 0, Math.PI * 2);
  ctx.fillStyle = warn;
  ctx.fill();
  ctx.lineWidth = 2;
  ctx.strokeStyle = "#0b0f1a";
  ctx.stroke();
}

// ---------------- trend chart ----------------

function renderTrendChart() {
  const labels = simData.history.map(r => `R${r.round}`);
  const vulnData = simData.history.map(r => r.vulnerable.malicious);
  const secureData = simData.history.map(r => r.secure.malicious);

  const tctx = document.getElementById("trendChart").getContext("2d");
  if (trendChart) trendChart.destroy();

  trendChart = new Chart(tctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Random selection",
          data: vulnData,
          borderColor: "#ff5c7a",
          backgroundColor: "rgba(255,92,122,0.15)",
          tension: 0.25,
          fill: true,
        },
        {
          label: "TABSD defense",
          data: secureData,
          borderColor: "#3ddc97",
          backgroundColor: "rgba(61,220,151,0.15)",
          tension: 0.25,
          fill: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { beginAtZero: true, suggestedMax: 8, ticks: { color: "#8b93ab" }, grid: { color: "#2a3350" } },
        x: { ticks: { color: "#8b93ab" }, grid: { color: "#2a3350" } },
      },
      plugins: { legend: { labels: { color: "#e7ebf5" } } },
    },
  });
}
