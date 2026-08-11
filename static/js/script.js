/* =========================================================
   CyberQuest CTF — static/js/script.js
   Multiplayer edition — client-side UI logic only.

   IMPORTANT: This file contains NO flags and performs NO flag
   comparison. Every flag submission is sent to the Flask server
   at /api/submit/<challenge-code>, which validates it against a
   securely hashed value in the SQLite database. The browser only
   ever learns whether its guess was "correct" / "incorrect" /
   "already-solved" — never the actual answer.
   ========================================================= */

const CTFApp = (() => {

  function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  function wireMobileNav() {
    const btn = document.querySelector(".hamburger");
    const links = document.querySelector(".nav-links");
    if (btn && links) {
      btn.addEventListener("click", () => links.classList.toggle("open"));
    }
  }

  function wireHintButton() {
    const btn = document.getElementById("hint-btn");
    const box = document.getElementById("hint-content");
    if (btn && box) {
      btn.addEventListener("click", () => {
        box.classList.toggle("show");
        btn.textContent = box.classList.contains("show") ? "Hide Hint" : "Show Hint";
      });
    }
  }

  /* ---------------- Flag submission (server-validated) ---------------- */

  function wireFlagForm() {
    const form = document.getElementById("flag-form");
    if (!form) return;

    const code = form.getAttribute("data-challenge-code");
    const input = document.getElementById("flag-input");
    const msg = document.getElementById("flag-msg");
    const solvedTag = document.getElementById("solved-tag");

    form.addEventListener("submit", async (e) => {
      e.preventDefault();

      const submitBtn = form.querySelector("button");
      submitBtn.disabled = true;

      try {
        const res = await fetch(`/api/submit/${encodeURIComponent(code)}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCsrfToken(),
          },
          credentials: "same-origin",
          body: JSON.stringify({ flag: input.value }),
        });

        if (res.status === 401) {
          window.location.href = "/login";
          return;
        }

        const data = await res.json();

        msg.classList.remove("correct", "incorrect");

        if (data.result === "correct") {
          msg.textContent = data.message || "Correct! Points added to your score.";
          msg.classList.add("correct");
          if (solvedTag) solvedTag.style.display = "inline-flex";
          input.disabled = true;
          // Reload shortly after so the nav score, solved badge, and
          // challenge list all reflect the authoritative server state.
          setTimeout(() => window.location.reload(), 1100);
        } else if (data.result === "already-solved") {
          msg.textContent = data.message || "You already solved this one!";
          msg.classList.add("correct");
          submitBtn.disabled = false;
        } else if (data.result === "event-ended") {
          msg.textContent = data.message || "CTF ENDED — submissions are closed.";
          msg.classList.add("incorrect");
        } else if (res.status === 429) {
          msg.textContent = data.error || "Too many attempts — please slow down.";
          msg.classList.add("incorrect");
          submitBtn.disabled = false;
        } else {
          msg.textContent = data.message || "Incorrect flag. Try again!";
          msg.classList.add("incorrect");
          submitBtn.disabled = false;
        }
      } catch (err) {
        msg.classList.remove("correct");
        msg.classList.add("incorrect");
        msg.textContent = "Network error — please try again.";
        submitBtn.disabled = false;
      }
    });
  }

  /* ---------------- Countdown (server time-synced) ---------------- */

  function startCountdown(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;

    let remaining = typeof window.CTF_EVENT_REMAINING === "number" ? window.CTF_EVENT_REMAINING : null;
    let ended = window.CTF_EVENT_ENDED === true;

    function render() {
      if (ended || remaining === null) {
        el.textContent = "CTF ENDED";
        return;
      }
      const h = String(Math.floor(remaining / 3600)).padStart(2, "0");
      const m = String(Math.floor((remaining % 3600) / 60)).padStart(2, "0");
      const s = String(Math.floor(remaining % 60)).padStart(2, "0");
      el.textContent = `${h}:${m}:${s}`;
    }

    async function resync() {
      try {
        const res = await fetch("/api/time-remaining");
        const data = await res.json();
        remaining = data.remaining_seconds;
        ended = data.ended;
        render();
      } catch (e) {
        // Keep ticking locally on the last known value if the fetch fails.
      }
    }

    render();
    // Local per-second tick between server resyncs, so it feels live.
    setInterval(() => {
      if (!ended && remaining !== null && remaining > 0) {
        remaining -= 1;
        render();
      }
    }, 1000);
    // Resync with the server periodically so a manipulated local clock
    // never actually extends the event.
    resync();
    setInterval(resync, 20000);
  }

  /* ---------------- Scoreboard polling ---------------- */

  function renderScoreboardRows(tbody, rows) {
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-dim);">No teams registered yet.</td></tr>';
      return;
    }
    const rankClass = ["rank-1", "rank-2", "rank-3"];
    tbody.innerHTML = rows.map((r, i) => `
      <tr class="${r.is_you ? "you" : ""}">
        <td class="${rankClass[i] || ""}">#${r.rank}</td>
        <td>${escapeHtml(r.team_name)}${r.is_you ? " (You)" : ""}</td>
        <td>${r.score} pts</td>
        <td>${r.solved} / ${r.total}</td>
      </tr>
    `).join("");
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function startScoreboardPolling(tbodyId) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;

    async function refresh() {
      try {
        const res = await fetch("/api/scoreboard");
        const data = await res.json();
        renderScoreboardRows(tbody, data.scoreboard);
      } catch (e) {
        // Keep showing the last successful render on transient errors.
      }
    }

    refresh();
    setInterval(refresh, 5000);
  }

  /* ---------------- Init ---------------- */

  document.addEventListener("DOMContentLoaded", () => {
    wireMobileNav();
  });

  return {
    wireHintButton,
    wireFlagForm,
    startCountdown,
    startScoreboardPolling,
  };
})();
