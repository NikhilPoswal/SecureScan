/* ════════════════════════════════════════════════════════════════════════
   SecureScan — main.js
   ════════════════════════════════════════════════════════════════════════ */
'use strict';

/* ────────────────────────────────────────────────────────────────────────
   Utility: ease-out cubic
   ──────────────────────────────────────────────────────────────────────── */
function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }

/* ────────────────────────────────────────────────────────────────────────
   Animated counter (counts up from 0 → target over `duration` ms)
   ──────────────────────────────────────────────────────────────────────── */
function animateCounter(el, target, duration) {
  if (!el) return;
  const start     = performance.now();
  const startVal  = 0;

  function frame(now) {
    const elapsed  = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased    = easeOutCubic(progress);
    el.textContent = Math.round(startVal + (target - startVal) * eased);
    if (progress < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

/* ────────────────────────────────────────────────────────────────────────
   Animated score bar (expands from 0 → target%)
   ──────────────────────────────────────────────────────────────────────── */
function animateScoreBar(el, target) {
  if (!el) return;
  // rAF double-tick ensures the CSS transition fires after display
  requestAnimationFrame(function () {
    requestAnimationFrame(function () {
      el.style.width = target + '%';
    });
  });
}

/* ────────────────────────────────────────────────────────────────────────
   Detail panel toggle (headers / cookies expandable rows)
   ──────────────────────────────────────────────────────────────────────── */
function toggleDetail(btn, panelId) {
  var panel  = document.getElementById(panelId);
  if (!panel) return;
  var isOpen = panel.classList.contains('open');

  panel.classList.toggle('open', !isOpen);
  btn.classList.toggle('open', !isOpen);
  btn.setAttribute('aria-expanded', String(!isOpen));

  // Update button label
  var label = btn.firstChild;
  if (label && label.nodeType === Node.TEXT_NODE) {
    var baseText = btn.dataset.baseLabel || btn.firstChild.textContent.trim().replace(/^Hide/, 'View').replace(/^View/, 'View');
    if (!btn.dataset.baseLabel) btn.dataset.baseLabel = baseText.replace(/^(View|Hide)\s/, '');
    label.textContent = (!isOpen ? 'Hide ' : 'View ') + btn.dataset.baseLabel + ' ';
  }
}

// Global event delegation for detail toggles (avoids inline onclick for strict CSP)
document.addEventListener('click', function (e) {
  var btn = e.target.closest('.detail-toggle');
  if (!btn) return;
  var panelId = btn.getAttribute('aria-controls') || btn.dataset.target;
  if (panelId) toggleDetail(btn, panelId);
});

/* ────────────────────────────────────────────────────────────────────────
   Homepage: scan form → loading state
   ──────────────────────────────────────────────────────────────────────── */
(function initScanForm() {
  var form    = document.getElementById('scan-form');
  var btn     = document.getElementById('scan-btn');
  var input   = document.getElementById('url-input');
  var btnText = document.getElementById('btn-text');
  var loader  = document.getElementById('btn-loader');

  if (!form || !btn) return;

  // Auto-focus input on load
  if (input) {
    input.focus();
    // Move cursor to end if pre-filled
    var len = input.value.length;
    input.setSelectionRange(len, len);
  }

  form.addEventListener('submit', function (e) {
    var val = (input ? input.value : '').trim();
    if (!val) {
      e.preventDefault();
      if (input) { input.focus(); shakeScanCard(); }
      return;
    }
    // Show loading state
    if (btnText) btnText.hidden = true;
    if (loader)  loader.hidden  = false;
    if (input)   input.readOnly = true;  // readOnly keeps value in POST body; disabled would drop it
    btn.disabled = true;
  });

  // Shake animation when empty submit attempted
  function shakeScanCard() {
    var card = document.getElementById('scan-card');
    if (!card) return;
    card.style.animation = 'none';
    card.offsetHeight; // reflow
    card.style.animation = 'shake 0.4s ease';
  }
})();

/* ────────────────────────────────────────────────────────────────────────
   Results page: counter + bar animations on load
   ──────────────────────────────────────────────────────────────────────── */
(function initResultsAnimations() {
  var counter = document.getElementById('score-counter');
  var bar     = document.getElementById('score-bar');
  if (!counter && !bar) return;  // not on results page

  var target = parseInt((counter || bar).dataset.target, 10) || 0;

  // Use IntersectionObserver so animations only fire when score card is visible
  var hero = document.querySelector('.score-hero');
  if (!hero) return;

  var triggered = false;
  function trigger() {
    if (triggered) return;
    triggered = true;
    // Short delay so grade circle scale-in finishes first
    setTimeout(function () {
      animateCounter(counter, target, 1200);
      animateScoreBar(bar, target);
    }, 280);
  }

  if ('IntersectionObserver' in window) {
    var obs = new IntersectionObserver(function (entries) {
      if (entries[0].isIntersecting) { trigger(); obs.disconnect(); }
    }, { threshold: 0.3 });
    obs.observe(hero);
  } else {
    trigger(); // fallback: fire immediately
  }
})();


