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
  var form       = document.getElementById('scan-form');
  var btn        = document.getElementById('scan-btn');
  var input      = document.getElementById('url-input');
  var btnText    = document.getElementById('btn-text');
  var loader     = document.getElementById('btn-loader');
  var loaderText = document.getElementById('btn-loader-text');

  if (!form || !btn) return;

  // Auto-focus input on load
  if (input) {
    input.focus();
    var len = input.value.length;
    input.setSelectionRange(len, len);
  }

  form.addEventListener('submit', function (e) {
    var val = (input ? input.value : '').replace(/\s+/g, '');
    if (!val) {
      e.preventDefault();
      if (input) { input.focus(); shakeCard(document.getElementById('scan-card')); }
      return;
    }
    if (input) input.value = val;

    // Show loading state for scan
    if (btnText) btnText.hidden = true;
    if (loader) loader.hidden = false;
    if (loaderText) loaderText.textContent = 'Scanning…';
    if (input) input.readOnly = true;
    btn.disabled = true;
  });

  // Shake animation when empty submit attempted
  function shakeCard(card) {
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

/* ────────────────────────────────────────────────────────────────────────
   Live Block Verifier (Replaces static timer with background status checks)
   ──────────────────────────────────────────────────────────────────────── */
(function initLiveBlockVerifier() {
  var card = document.getElementById('cooldown-card');
  if (!card) return;

  var elapsedEl = document.getElementById('cooldown-elapsed');
  var pollStatusEl = document.getElementById('cooldown-poll-status');
  var pollTextEl = document.getElementById('cooldown-poll-text');
  var badgeEl = document.getElementById('cooldown-badge');
  var badgeTextEl = document.getElementById('cooldown-badge-text');
  var retryBtn = document.getElementById('cooldown-retry-btn');
  var noteEl = document.getElementById('cooldown-note');
  var urlInput = document.getElementById('url-input');
  var scanForm = document.getElementById('scan-form');

  var targetUrl = card.dataset.targetUrl || (urlInput ? urlInput.value : '');
  if (!targetUrl) return;

  var storageKey = 'securescan_blocked_' + encodeURIComponent(targetUrl);
  var stored = null;
  try {
    var item = sessionStorage.getItem(storageKey);
    if (item) stored = JSON.parse(item);
  } catch (e) {}

  var now = Date.now();
  var MAX_DURATION_SEC = 1800; // 30 minute cap
  var POLL_INTERVAL_MS = 30000; // 30 seconds
  var isCleared = false;
  var isCapped = false;
  var isChecking = false;

  var blockedAt;
  if (stored && stored.blockedAt && (now - stored.blockedAt < MAX_DURATION_SEC * 1000)) {
    blockedAt = stored.blockedAt;
  } else {
    blockedAt = now;
    try {
      sessionStorage.setItem(storageKey, JSON.stringify({ blockedAt: blockedAt }));
    } catch (e) {}
  }

  function formatElapsed(sec) {
    var m = Math.floor(sec / 60);
    var s = sec % 60;
    return m + 'm ' + (s < 10 ? '0' : '') + s + 's';
  }

  function updateElapsed() {
    if (isCleared || isCapped) return;
    var elapsedSec = Math.floor((Date.now() - blockedAt) / 1000);
    if (elapsedSec >= MAX_DURATION_SEC) {
      isCapped = true;
      if (pollTextEl) {
        pollTextEl.textContent = 'Automatic checks paused after 30 minutes. You can still test manually whenever ready.';
      }
      if (pollStatusEl) {
        pollStatusEl.classList.remove('status-checking');
      }
      stopAll();
      return;
    }
    if (elapsedEl) {
      elapsedEl.textContent = formatElapsed(elapsedSec);
    }
  }

  function markAsCleared(statusMsg) {
    isCleared = true;
    stopAll();

    if (card) {
      card.classList.add('cleared');
    }
    if (badgeEl) {
      badgeEl.className = 'cooldown-badge badge-cleared';
    }
    if (badgeTextEl) {
      badgeTextEl.textContent = '✅ Looks Clear — Ready to Re-scan';
    }
    if (elapsedEl) {
      elapsedEl.classList.add('timer-cleared');
    }
    if (pollStatusEl) {
      pollStatusEl.className = 'cooldown-poll-status status-cleared';
    }
    if (pollTextEl) {
      pollTextEl.textContent = statusMsg || 'Target is responding normally! You can re-scan now.';
    }
    if (retryBtn) {
      retryBtn.className = 'btn btn-primary btn-sm cooldown-retry-btn btn-ready';
      retryBtn.textContent = '🚀 Re-scan Now';
    }
    if (noteEl) {
      noteEl.textContent = 'Target is responsive. Click to run a full security audit.';
      noteEl.style.color = 'var(--green)';
    }

    try {
      sessionStorage.removeItem(storageKey);
    } catch (e) {}
  }

  function checkTargetStatus() {
    if (isCleared || isCapped || isChecking) return;
    isChecking = true;

    if (pollTextEl && !isCleared) {
      pollTextEl.textContent = 'Checking target in background...';
    }

    var checkUrl = '/check-status?url=' + encodeURIComponent(targetUrl);
    fetch(checkUrl, { method: 'GET', headers: { 'Accept': 'application/json' } })
      .then(function (res) {
        if (!res.ok) {
          throw new Error('HTTP ' + res.status);
        }
        return res.json();
      })
      .then(function (data) {
        isChecking = false;
        if (data.is_clear) {
          markAsCleared('✅ Target responded with HTTP ' + (data.status || 200) + ' — ready to re-scan!');
        } else if (data.is_blocked) {
          if (pollTextEl) {
            pollTextEl.textContent = 'Still blocked (HTTP ' + data.status + '). Next check in 30s...';
          }
          if (noteEl) {
            noteEl.textContent = 'Still checking... target may still be blocked';
            noteEl.style.color = 'var(--text-muted)';
          }
        } else {
          if (pollTextEl) {
            pollTextEl.textContent = 'Target returned HTTP ' + data.status + '. Next check in 30s...';
          }
        }
      })
      .catch(function (err) {
        isChecking = false;
        if (pollTextEl && !isCleared) {
          pollTextEl.textContent = 'Background check delayed. Will retry in 30s...';
        }
      });
  }

  // Update elapsed time every 1s
  updateElapsed();
  var elapsedTimer = setInterval(updateElapsed, 1000);

  // Poll target status every 30s
  var pollTimer = setInterval(checkTargetStatus, POLL_INTERVAL_MS);

  // If already waited over 20s when loading the page, check quickly
  var initialElapsed = Math.floor((Date.now() - blockedAt) / 1000);
  if (initialElapsed >= 20) {
    setTimeout(checkTargetStatus, 3000);
  }

  function stopAll() {
    if (elapsedTimer) clearInterval(elapsedTimer);
    if (pollTimer) clearInterval(pollTimer);
  }

  window.addEventListener('beforeunload', stopAll);
  window.addEventListener('pagehide', stopAll);

  // Manual retry handler (available at all times)
  if (retryBtn) {
    retryBtn.addEventListener('click', function () {
      stopAll();
      if (urlInput && targetUrl) {
        urlInput.value = targetUrl;
      }
      if (scanForm) {
        scanForm.requestSubmit ? scanForm.requestSubmit() : scanForm.submit();
      }
    });
  }
})();

/* ────────────────────────────────────────────────────────────────────────
   Session Scan History (sessionStorage only, last 5 scans)
   ──────────────────────────────────────────────────────────────────────── */
(function initSessionScanHistory() {
  var STORAGE_KEY = 'securescan_session_history';
  var MAX_HISTORY = 5;
  var activeHistoryIndex = 0;

  function getHistory() {
    try {
      var raw = sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      var parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }

  function saveHistory(list) {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(list));
    } catch (e) {}
  }

  function formatRelativeTime(storedAt) {
    if (!storedAt) return 'just now';
    var diffSec = Math.max(0, Math.floor((Date.now() - storedAt) / 1000));
    if (diffSec < 15) return 'just now';
    if (diffSec < 60) return diffSec + 's ago';
    var diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return diffMin + 'm ago';
    var diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return diffHours + 'h ago';
    return Math.floor(diffHours / 24) + 'd ago';
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatDisplayUrl(url) {
    if (!url) return '';
    return String(url).replace(/^https?:\/\//i, '').replace(/\/$/, '');
  }

  // 1. Record current scan on results page
  var reportInput = document.querySelector('input[name="report_data"]');
  if (reportInput && reportInput.value) {
    try {
      var rawPayload = reportInput.value;
      var scanObj = JSON.parse(atob(rawPayload));
      var targetUrl = (scanObj.url || '').trim();
      var finalUrl = (scanObj.final_url || targetUrl).trim();
      var scoreVal = parseInt(scanObj.score, 10) || 0;
      var gradeVal = String(scanObj.grade || 'F').toUpperCase();
      var timeStr = scanObj.timestamp || new Date().toUTCString();

      var newEntry = {
        url: targetUrl,
        final_url: finalUrl,
        score: scoreVal,
        grade: gradeVal,
        timestamp: timeStr,
        stored_at: Date.now(),
        report_data: rawPayload,
        checks: scanObj.checks || []
      };

      var history = getHistory();
      // Deduplicate: remove existing entry matching same url or final_url
      history = history.filter(function (item) {
        return item.url.toLowerCase() !== targetUrl.toLowerCase() &&
               item.final_url.toLowerCase() !== finalUrl.toLowerCase();
      });

      // Insert at beginning
      history.unshift(newEntry);

      // Keep only most recent 5 (Requirement 1: drop oldest when 6th added)
      if (history.length > MAX_HISTORY) {
        history = history.slice(0, MAX_HISTORY);
      }

      saveHistory(history);
      activeHistoryIndex = 0;
    } catch (e) {
      console.warn('Unable to record scan to sessionStorage:', e);
    }
  }

  // 2. Render Results Page UI
  function renderResultsPageHistory() {
    var history = getHistory();
    var countBadge = document.getElementById('history-count-badge');
    var container = document.getElementById('history-items-container');
    var bar = document.getElementById('session-history-bar');
    var pillsContainer = document.getElementById('history-pills-container');

    if (countBadge) {
      countBadge.textContent = String(history.length);
      countBadge.className = 'history-count-badge' + (history.length > 0 ? ' has-items' : '');
    }

    // Dropdown items
    if (container) {
      if (history.length === 0) {
        container.innerHTML =
          '<div class="history-empty-state">' +
            '<span class="history-empty-icon" aria-hidden="true">🕒</span>' +
            '<p class="history-empty-title">No previous scans yet</p>' +
            '<p class="history-empty-hint">Scans during this tab session will appear here for instant review.</p>' +
          '</div>';
      } else {
        var html = '';
        history.forEach(function (item, idx) {
          var isActive = (idx === activeHistoryIndex);
          var gradeClass = 'grade-' + item.grade.toLowerCase();
          var displayHost = formatDisplayUrl(item.url);
          html +=
            '<button type="button" class="history-item-btn ' + (isActive ? 'active' : '') + '" data-history-idx="' + idx + '" role="menuitem" aria-label="Restore scan for ' + escapeHtml(item.url) + ', Score ' + item.score + ' of 100, Grade ' + item.grade + '">' +
              '<div class="history-item-col-left">' +
                '<span class="history-grade-pill ' + gradeClass + '">' + item.grade + '</span>' +
                '<div class="history-item-meta">' +
                  '<span class="history-item-url" title="' + escapeHtml(item.url) + '">' + escapeHtml(displayHost) + '</span>' +
                  '<span class="history-item-time">' + formatRelativeTime(item.stored_at) + '</span>' +
                '</div>' +
              '</div>' +
              '<div class="history-item-col-right">' +
                '<span class="history-item-score-val">' + item.score + '<span class="history-score-denom">/100</span></span>' +
                (isActive ? '<span class="history-active-indicator">Viewing</span>' : '') +
              '</div>' +
            '</button>';
        });
        container.innerHTML = html;
      }
    }

    // Horizontal quick switcher bar
    if (bar && pillsContainer) {
      if (history.length <= 1) {
        bar.hidden = true;
      } else {
        bar.hidden = false;
        var pillsHtml = '';
        history.forEach(function (item, idx) {
          var isActive = (idx === activeHistoryIndex);
          var gradeClass = 'grade-' + item.grade.toLowerCase();
          var timeStr = formatRelativeTime(item.stored_at);
          var displayHost = formatDisplayUrl(item.url);
          pillsHtml +=
            '<button type="button" class="history-pill ' + (isActive ? 'active' : '') + '" data-history-idx="' + idx + '" aria-label="Switch to scan for ' + escapeHtml(item.url) + ', Grade ' + item.grade + ', ' + item.score + ' of 100" title="View stored scan for ' + escapeHtml(item.url) + '">' +
              '<span class="history-pill-dot ' + gradeClass + '" aria-hidden="true"></span>' +
              '<span class="history-pill-host">' + escapeHtml(displayHost) + '</span>' +
              '<span class="history-pill-sep" aria-hidden="true">|</span>' +
              '<span class="history-pill-grade ' + gradeClass + '">Grade ' + item.grade + '</span>' +
              '<span class="history-pill-sep" aria-hidden="true">|</span>' +
              '<span class="history-pill-score">' + item.score + '<span class="history-pill-denom">/100</span></span>' +
              '<span class="history-pill-sep" aria-hidden="true">|</span>' +
              '<span class="history-pill-time">' + timeStr + '</span>' +
            '</button>';
        });
        pillsContainer.innerHTML = pillsHtml;
      }
    }
  }

  // 3. Instant In-Place Re-render (Requirement 3 & 5)
  function restoreScan(idx) {
    var history = getHistory();
    if (!history || !history[idx]) return;
    var item = history[idx];
    activeHistoryIndex = idx;

    // 1. Scanned URL display
    var scannedUrlEl = document.querySelector('.scanned-url');
    if (scannedUrlEl) {
      scannedUrlEl.textContent = item.final_url || item.url;
    }

    // 2. Score counter & track
    var scoreCounter = document.getElementById('score-counter');
    var scoreBar = document.getElementById('score-bar');
    if (scoreCounter) {
      scoreCounter.dataset.target = item.score;
      animateCounter(scoreCounter, item.score, 450);
    }
    if (scoreBar) {
      scoreBar.dataset.target = item.score;
      scoreBar.style.width = item.score + '%';
    }

    // 3. Hero & Grade badge
    var gradeClass = 'grade-' + item.grade.toLowerCase();
    var heroSection = document.querySelector('.score-hero');
    if (heroSection) {
      heroSection.className = 'score-hero ' + gradeClass;
      heroSection.setAttribute('aria-label', 'Overall security score: ' + item.score + ' out of 100, Grade ' + item.grade);
    }
    var gradeCircle = document.querySelector('.grade-circle');
    if (gradeCircle) {
      gradeCircle.className = 'grade-circle ' + gradeClass;
    }
    var gradeLetter = document.querySelector('.grade-letter');
    if (gradeLetter) {
      gradeLetter.textContent = item.grade;
    }

    // 4. Update the 10 check cards
    var cards = document.querySelectorAll('.checks-list .check-card');
    if (item.checks && item.checks.length) {
      item.checks.forEach(function (c, i) {
        var card = cards[i];
        if (!card) return;

        // Pass/Fail class
        card.className = 'check-card ' + (c.passed ? 'pass' : 'fail');
        card.setAttribute('role', 'region');
        var deductedStr = c.deducted > 0 ? (c.deducted + ' points deducted') : '0 points deducted';
        var statusStr = c.passed ? 'Passed (0 points deducted)' : ('Failed (' + deductedStr + ')');
        card.setAttribute('aria-label', 'Check ' + (i + 1) + ' of 10: ' + c.name + '. Status: ' + statusStr);

        // Status icon
        var iconEl = card.querySelector('.status-icon');
        if (iconEl) iconEl.textContent = c.passed ? '✅' : '❌';

        // Title
        var titleEl = card.querySelector('.card-title');
        if (titleEl) titleEl.textContent = c.name;

        // Category
        var catEl = card.querySelector('.category-badge');
        if (catEl && c.category) catEl.textContent = c.category;

        // Subtitle
        var subEl = card.querySelector('.card-subtitle');
        if (subEl) {
          subEl.textContent = c.passed ? 'Passed — no issues found' : 'Failed — action recommended';
        }

        // Deduction pill
        var pill = card.querySelector('.deduct-pill');
        if (pill) {
          if (c.deducted > 0) {
            pill.className = 'deduct-pill has-deduction';
            pill.setAttribute('aria-label', 'minus ' + c.deducted + ' points');
            pill.textContent = '−' + c.deducted + ' pts';
          } else {
            pill.className = 'deduct-pill no-deduction';
            pill.setAttribute('aria-label', 'no points deducted');
            pill.textContent = '✓ 0 pts';
          }
        }

        // Explanation text
        var expEl = card.querySelector('.card-explanation');
        if (expEl) expEl.textContent = c.explanation;

        // Hide old detail toggles & panels on restored card for consistency
        var toggleBtn = card.querySelector('.detail-toggle');
        var detailPanel = card.querySelector('.detail-panel');
        if (toggleBtn) toggleBtn.style.display = 'none';
        if (detailPanel) detailPanel.style.display = 'none';
      });
    }

    // 5. REQUIREMENT 5: Update hidden PDF export inputs so Download PDF generates for restored result
    var pdfInputs = document.querySelectorAll('input[name="report_data"]');
    pdfInputs.forEach(function (input) {
      input.value = item.report_data;
    });

    // 6. Flash confirmation toast
    var notice = document.getElementById('history-restore-notice');
    var noticeText = document.getElementById('history-restore-text');
    if (notice && noticeText) {
      noticeText.textContent = 'Restored ' + item.url + ' (' + item.score + '/100, Grade ' + item.grade + ') — PDF export updated';
      notice.hidden = false;
      notice.classList.remove('hiding');
      notice.classList.add('visible');
      clearTimeout(notice._timer);
      notice._timer = setTimeout(function () {
        notice.classList.remove('visible');
        notice.classList.add('hiding');
        setTimeout(function () { notice.hidden = true; }, 300);
      }, 3000);
    }

    // 7. Update UI active states
    renderResultsPageHistory();

    // 8. Close dropdown if open and restore focus to toggle button
    var wasInside = dropdownMenu && dropdownMenu.contains(document.activeElement);
    closeDropdown(wasInside);
  }

  // 4. Dropdown Toggle and Controls
  var dropdownWrap = document.getElementById('history-dropdown-wrap');
  var toggleBtn = document.getElementById('history-toggle-btn');
  var dropdownMenu = document.getElementById('history-dropdown-menu');
  var clearBtn = document.getElementById('history-clear-btn');

  function openDropdown(focusFirst) {
    if (!dropdownMenu || !toggleBtn) return;
    dropdownMenu.hidden = false;
    toggleBtn.setAttribute('aria-expanded', 'true');
    toggleBtn.classList.add('active');
    if (focusFirst) {
      setTimeout(function () {
        var firstItem = dropdownMenu.querySelector('.history-item-btn, #history-clear-btn');
        if (firstItem) firstItem.focus();
      }, 50);
    }
  }

  function closeDropdown(returnFocus) {
    if (!dropdownMenu || !toggleBtn) return;
    dropdownMenu.hidden = true;
    toggleBtn.setAttribute('aria-expanded', 'false');
    toggleBtn.classList.remove('active');
    if (returnFocus && toggleBtn) {
      toggleBtn.focus();
    }
  }

  if (toggleBtn) {
    toggleBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      var isOpen = (toggleBtn.getAttribute('aria-expanded') === 'true');
      if (isOpen) {
        closeDropdown(false);
      } else {
        openDropdown(false);
      }
    });

    toggleBtn.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        var isOpen = (toggleBtn.getAttribute('aria-expanded') === 'true');
        if (!isOpen) {
          openDropdown(true);
        } else {
          var firstItem = dropdownMenu.querySelector('.history-item-btn, #history-clear-btn');
          if (firstItem) firstItem.focus();
        }
      }
    });
  }

  // Keyboard navigation inside history dropdown menu
  if (dropdownMenu) {
    dropdownMenu.addEventListener('keydown', function (e) {
      var items = Array.prototype.slice.call(
        dropdownMenu.querySelectorAll('.history-item-btn, #history-clear-btn')
      );
      if (!items.length) return;
      var currentIndex = items.indexOf(document.activeElement);

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        var nextIndex = (currentIndex + 1) % items.length;
        items[nextIndex].focus();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        var prevIndex = (currentIndex - 1 + items.length) % items.length;
        items[prevIndex].focus();
      } else if (e.key === 'Home') {
        e.preventDefault();
        items[0].focus();
      } else if (e.key === 'End') {
        e.preventDefault();
        items[items.length - 1].focus();
      } else if (e.key === 'Tab') {
        if (e.shiftKey && currentIndex <= 0) {
          closeDropdown(true);
        } else if (!e.shiftKey && currentIndex >= items.length - 1) {
          closeDropdown(false);
        }
      }
    });
  }

  // Close dropdown on click outside
  document.addEventListener('click', function (e) {
    if (dropdownWrap && !dropdownWrap.contains(e.target)) {
      closeDropdown(false);
    }
  });

  // Close on Escape key
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && dropdownMenu && !dropdownMenu.hidden) {
      closeDropdown(true);
    }
  });

  // Clear history handler
  if (clearBtn) {
    clearBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      sessionStorage.removeItem(STORAGE_KEY);
      activeHistoryIndex = -1;
      renderResultsPageHistory();
      renderHomePageHistory();
    });
  }

  // Delegated click handler for history item buttons in dropdown and quick switcher
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-history-idx]');
    if (!btn) return;
    e.preventDefault();
    var idx = parseInt(btn.getAttribute('data-history-idx'), 10);
    if (!isNaN(idx)) {
      restoreScan(idx);
    }
  });

  // 5. Homepage History Render
  function renderHomePageHistory() {
    var section = document.getElementById('home-history-section');
    var list = document.getElementById('home-history-list');
    var homeClearBtn = document.getElementById('home-history-clear-btn');
    if (!section || !list) return;

    var history = getHistory();
    if (history.length === 0) {
      section.hidden = true;
      return;
    }

    section.hidden = false;
    var html = '';
    history.forEach(function (item) {
      var gradeClass = 'grade-' + item.grade.toLowerCase();
      var timeStr = formatRelativeTime(item.stored_at);
      var displayHost = formatDisplayUrl(item.url);
      html +=
        '<button type="button" class="home-history-pill" data-fill-url="' + escapeHtml(item.url) + '" aria-label="Fill ' + escapeHtml(item.url) + ' (Grade ' + item.grade + ', ' + item.score + ' of 100, ' + timeStr + ') to scan again" title="Fill ' + escapeHtml(item.url) + ' to scan again">' +
          '<span class="history-pill-dot ' + gradeClass + '" aria-hidden="true"></span>' +
          '<span class="home-history-host">' + escapeHtml(displayHost) + '</span>' +
          '<span class="history-pill-sep" aria-hidden="true">|</span>' +
          '<span class="history-pill-grade ' + gradeClass + '">Grade ' + item.grade + '</span>' +
          '<span class="history-pill-sep" aria-hidden="true">|</span>' +
          '<span class="history-pill-score">' + item.score + '<span class="history-pill-denom">/100</span></span>' +
          '<span class="history-pill-sep" aria-hidden="true">|</span>' +
          '<span class="history-pill-time">' + timeStr + '</span>' +
        '</button>';
    });
    list.innerHTML = html;

    if (homeClearBtn) {
      homeClearBtn.onclick = function () {
        sessionStorage.removeItem(STORAGE_KEY);
        activeHistoryIndex = -1;
        section.hidden = true;
        renderResultsPageHistory();
      };
    }
  }

  // Handle clicking a home history pill to fill the search box
  document.addEventListener('click', function (e) {
    var pill = e.target.closest('[data-fill-url]');
    if (!pill) return;
    var url = pill.getAttribute('data-fill-url');
    var input = document.getElementById('url-input');
    if (input && url) {
      input.value = url;
      input.focus();
    }
  });

  // Initial render on page load
  renderResultsPageHistory();
  renderHomePageHistory();
})();
