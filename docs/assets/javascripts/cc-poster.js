/**
 * Command & Code — Cheat Sheet Speed Dial & Tailor HUD Engine
 * Enhances standard markdown cheat sheets with a high-yield Heads-Up Display (HUD):
 *   - Topic Speed Dial: Quick jump pills to all sections with glowing target pulses
 *   - Live Parameter Tailor: In-place dynamic injection for <USER>, <HOST>, <SERVICE>, etc.
 *   - Fast In-Page Filter: Real-time search highlighting across commands and tables
 *   - Widescreen Terminal Mode: Expandable reading canvas for long admin one-liners
 *
 * Fully preserves MkDocs default webpage layout, TOC, navigation, and deep linking.
 */
(function () {
  'use strict';

  function isCheatSheetPage() {
    var path = window.location.pathname.toLowerCase();
    return path.indexOf('cheat-sheet') !== -1 ||
           path.indexOf('/references/') !== -1 ||
           document.querySelector('.cc-interactive-poster');
  }

  function initHud() {
    if (!isCheatSheetPage()) return;

    var content = document.querySelector('.md-content__inner');
    if (!content) return;

    // Avoid double initialization
    if (content.querySelector('.cc-speed-dial-hud')) return;

    var h2Elements = Array.from(content.querySelectorAll('h2')).filter(function (h2) {
      var txt = h2.textContent.toLowerCase();
      return txt.indexOf('related') === -1 && txt.indexOf('sources') === -1;
    });

    if (h2Elements.length === 0) return;

    // Cache original HTML of all code blocks and table codes for live tailoring
    var codeElements = Array.from(content.querySelectorAll('.highlight pre > code, table code'));
    codeElements.forEach(function (el) {
      if (!el.dataset.ccOriginalHtml) {
        el.dataset.ccOriginalHtml = el.innerHTML;
      }
    });

    // Detect placeholders on the page
    var pageText = content.textContent;
    var hasUser = /<USER>|<user_name>|<username>/i.test(pageText);
    var hasService = /<service_name>|<SERVICE_NAME>/i.test(pageText);
    var hasHost = /<TARGET_HOST>|<target_host>|<host>/i.test(pageText);
    var hasPort = /<PORT>|<port>/i.test(pageText);

    // Build the HUD container
    var hud = document.createElement('div');
    hud.className = 'cc-speed-dial-hud';

    // Header strip with title, match counter, and controls
    var topRow = document.createElement('div');
    topRow.className = 'cc-hud-top-row';

    var titleBox = document.createElement('div');
    titleBox.className = 'cc-hud-title-box';
    titleBox.innerHTML =
      '<span class="cc-hud-badge">HUD</span>' +
      '<span class="cc-hud-title">Command Speed Dial &amp; Live Tailor</span>';

    var controlsBox = document.createElement('div');
    controlsBox.className = 'cc-hud-controls';

    // Search / Fast Filter Box
    var searchWrap = document.createElement('div');
    searchWrap.className = 'cc-hud-search-wrap';
    searchWrap.innerHTML =
      '<span class="cc-hud-search-icon">🔍</span>' +
      '<input type="text" class="cc-hud-search-input" placeholder="Fast filter commands (e.g. systemctl, pkill, port)..." aria-label="Fast filter commands">' +
      '<span class="cc-hud-match-count cc-hidden">0 matches</span>';

    // Breakout Command Wall Toggle
    var wideBtn = document.createElement('button');
    wideBtn.className = 'cc-hud-btn cc-hud-wide-btn';
    wideBtn.type = 'button';
    wideBtn.title = 'Break out of standard page format into full-canvas Command Poster Wall';
    wideBtn.innerHTML = '<span class="cc-hud-btn-icon">⛶</span> Breakout Wall [ON]';

    controlsBox.appendChild(searchWrap);
    controlsBox.appendChild(wideBtn);

    topRow.appendChild(titleBox);
    topRow.appendChild(controlsBox);
    hud.appendChild(topRow);

    // 1. Topic Speed Dial Navigator (Pills)
    var navRow = document.createElement('div');
    navRow.className = 'cc-hud-nav-row';

    var navLabel = document.createElement('span');
    navLabel.className = 'cc-hud-nav-label';
    navLabel.textContent = 'Topic Jump:';
    navRow.appendChild(navLabel);

    var pillsWrap = document.createElement('div');
    pillsWrap.className = 'cc-hud-pills-wrap';

    h2Elements.forEach(function (h2) {
      var raw = h2.textContent.trim();
      var clean = raw.replace(/^[0-9.]+\s*/, '').trim();
      var icon = determineSectionIcon(raw);

      var pill = document.createElement('a');
      pill.className = 'cc-hud-pill';
      pill.href = '#' + (h2.id || encodeURIComponent(clean.toLowerCase().replace(/\s+/g, '-')));
      pill.innerHTML = '<span class="cc-hud-pill-icon">' + icon + '</span> ' + escapeHtml(clean);

      pill.addEventListener('click', function (e) {
        e.preventDefault();
        h2.scrollIntoView({ behavior: 'smooth', block: 'start' });
        highlightSection(h2);
        try {
          history.pushState(null, null, '#' + h2.id);
        } catch (err) {}
      });

      pillsWrap.appendChild(pill);
    });

    navRow.appendChild(pillsWrap);
    hud.appendChild(navRow);

    // 2. Live Parameter Tailor Bar
    var tailorRow = document.createElement('div');
    tailorRow.className = 'cc-hud-tailor-row';

    var tailorLabel = document.createElement('span');
    tailorLabel.className = 'cc-hud-tailor-label';
    tailorLabel.innerHTML = '⚡ <strong>Live Parameter Tailor:</strong>';
    tailorRow.appendChild(tailorLabel);

    var paramsWrap = document.createElement('div');
    paramsWrap.className = 'cc-hud-params-wrap';

    var defaultParams = [];
    if (hasService || (!hasUser && !hasHost)) {
      defaultParams.push({ id: 'SERVICE', label: 'Service', defaultVal: 'nginx', placeholder: 'nginx' });
    }
    if (hasUser || (!hasService && !hasHost)) {
      defaultParams.push({ id: 'USER', label: 'User', defaultVal: 'admin', placeholder: 'admin' });
    }
    if (hasHost) {
      defaultParams.push({ id: 'HOST', label: 'Host', defaultVal: 'srv-app-01', placeholder: 'srv-app-01' });
    }
    if (hasPort) {
      defaultParams.push({ id: 'PORT', label: 'Port', defaultVal: '8080', placeholder: '8080' });
    }

    defaultParams.forEach(function (p) {
      var group = document.createElement('div');
      group.className = 'cc-hud-param-group';
      group.innerHTML =
        '<label class="cc-hud-param-lbl">' + escapeHtml(p.label) + ':</label>' +
        '<input type="text" class="cc-hud-param-input" data-param-id="' + p.id + '" value="' + escapeAttr(p.defaultVal) + '" placeholder="' + escapeAttr(p.placeholder) + '">';
      paramsWrap.appendChild(group);
    });

    var resetBtn = document.createElement('button');
    resetBtn.className = 'cc-hud-reset-btn';
    resetBtn.type = 'button';
    resetBtn.title = 'Reset to original template placeholders';
    resetBtn.innerHTML = '↺ Reset';
    paramsWrap.appendChild(resetBtn);

    tailorRow.appendChild(paramsWrap);
    hud.appendChild(tailorRow);

    // Insert HUD right beneath page title / meta strip
    var h1 = content.querySelector('h1');
    var metaStrip = content.querySelector('.cc-meta') || content.querySelector('.cc-aliases');
    var insertTarget = metaStrip ? metaStrip.nextSibling : (h1 ? h1.nextSibling : content.firstChild);
    content.insertBefore(hud, insertTarget);

    // Build the responsive multi-column Poster Deck from markdown sections
    buildPosterDeck(content, h2Elements);

    // Breakout Mode: defaults to ON for reference cheat sheets
    var savedBreakout = null;
    try {
      savedBreakout = localStorage.getItem('cc-breakout');
    } catch (e) {}

    var isBreakoutActive = savedBreakout !== 'false';
    if (isBreakoutActive) {
      document.body.classList.add('cc-breakout-mode');
      wideBtn.classList.add('cc-active');
      wideBtn.innerHTML = '<span class="cc-hud-btn-icon">⛶</span> Breakout Wall [ON]';
    } else {
      document.body.classList.remove('cc-breakout-mode');
      wideBtn.classList.remove('cc-active');
      wideBtn.innerHTML = '<span class="cc-hud-btn-icon">⛶</span> Breakout Wall';
    }

    wideBtn.addEventListener('click', function () {
      var active = document.body.classList.toggle('cc-breakout-mode');
      wideBtn.classList.toggle('cc-active', active);
      wideBtn.innerHTML = active
        ? '<span class="cc-hud-btn-icon">⛶</span> Breakout Wall [ON]'
        : '<span class="cc-hud-btn-icon">⛶</span> Breakout Wall';
      try {
        localStorage.setItem('cc-breakout', active ? 'true' : 'false');
      } catch (e) {}
    });

    // Event: Live Search / Filter
    var searchInput = searchWrap.querySelector('.cc-hud-search-input');
    var countBadge = searchWrap.querySelector('.cc-hud-match-count');
    var matchesList = [];
    var currentMatchIdx = -1;

    searchInput.addEventListener('input', function () {
      var q = searchInput.value.toLowerCase().trim();
      matchesList = [];
      currentMatchIdx = -1;

      var allBlocks = Array.from(content.querySelectorAll('.highlight, table tbody tr'));
      var allCards = Array.from(content.querySelectorAll('.cc-poster-card'));

      if (!q) {
        allBlocks.forEach(function (el) {
          el.classList.remove('cc-hud-match', 'cc-hud-dimmed', 'cc-hud-active-match');
        });
        allCards.forEach(function (card) {
          card.classList.remove('cc-card-dimmed');
        });
        countBadge.classList.add('cc-hidden');
        return;
      }

      allBlocks.forEach(function (el) {
        var text = el.textContent.toLowerCase();
        if (text.indexOf(q) !== -1) {
          el.classList.add('cc-hud-match');
          el.classList.remove('cc-hud-dimmed');
          matchesList.push(el);
        } else {
          el.classList.remove('cc-hud-match', 'cc-hud-active-match');
          el.classList.add('cc-hud-dimmed');
        }
      });

      allCards.forEach(function (card) {
        var hasMatch = card.querySelector('.cc-hud-match');
        card.classList.toggle('cc-card-dimmed', !hasMatch);
      });

      countBadge.textContent = matchesList.length + (matchesList.length === 1 ? ' match' : ' matches');
      countBadge.classList.remove('cc-hidden');
    });

    searchInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && matchesList.length > 0) {
        e.preventDefault();
        currentMatchIdx = (currentMatchIdx + 1) % matchesList.length;
        matchesList.forEach(function (el, idx) {
          el.classList.toggle('cc-hud-active-match', idx === currentMatchIdx);
        });
        matchesList[currentMatchIdx].scrollIntoView({ behavior: 'smooth', block: 'center' });
      } else if (e.key === 'Escape') {
        searchInput.value = '';
        searchInput.dispatchEvent(new Event('input'));
        searchInput.blur();
      }
    });

    // Event: Parameter Tailoring
    function applyTailor() {
      var inputs = Array.from(paramsWrap.querySelectorAll('.cc-hud-param-input'));
      var values = {};
      inputs.forEach(function (inp) {
        values[inp.dataset.paramId] = inp.value.trim();
      });

      codeElements.forEach(function (el) {
        var baseHtml = el.dataset.ccOriginalHtml;
        if (!baseHtml) return;

        var modified = baseHtml;

        if (values.SERVICE) {
          var sVal = '<span class="cc-param-tailored">' + escapeHtml(values.SERVICE) + '</span>';
          modified = modified.replace(/&lt;service_name&gt;|<service_name>|&lt;SERVICE_NAME&gt;|<SERVICE_NAME>/g, sVal);
        }
        if (values.USER) {
          var uVal = '<span class="cc-param-tailored">' + escapeHtml(values.USER) + '</span>';
          modified = modified.replace(/&lt;USER&gt;|<USER>|&lt;user_name&gt;|<user_name>|&lt;username&gt;|<username>/g, uVal);
        }
        if (values.HOST) {
          var hVal = '<span class="cc-param-tailored">' + escapeHtml(values.HOST) + '</span>';
          modified = modified.replace(/&lt;TARGET_HOST&gt;|<TARGET_HOST>|&lt;target_host&gt;|<target_host>/g, hVal);
        }
        if (values.PORT) {
          var pVal = '<span class="cc-param-tailored">' + escapeHtml(values.PORT) + '</span>';
          modified = modified.replace(/&lt;PORT&gt;|<PORT>/g, pVal);
        }

        el.innerHTML = modified;
      });
    }

    paramsWrap.querySelectorAll('.cc-hud-param-input').forEach(function (inp) {
      inp.addEventListener('input', applyTailor);
    });

    resetBtn.addEventListener('click', function () {
      paramsWrap.querySelectorAll('.cc-hud-param-input').forEach(function (inp) {
        inp.value = '';
      });
      codeElements.forEach(function (el) {
        if (el.dataset.ccOriginalHtml) {
          el.innerHTML = el.dataset.ccOriginalHtml;
        }
      });
    });

    // Run initial tailoring with defaults
    applyTailor();
  }

  function highlightSection(heading) {
    heading.classList.remove('cc-heading-focus');
    // Trigger reflow for animation restart
    void heading.offsetWidth;
    heading.classList.add('cc-heading-focus');

    var parentCard = heading.closest('.cc-poster-card');
    if (parentCard) {
      parentCard.classList.remove('cc-card-focus');
      void parentCard.offsetWidth;
      parentCard.classList.add('cc-card-focus');
    }

    setTimeout(function () {
      heading.classList.remove('cc-heading-focus');
      if (parentCard) parentCard.classList.remove('cc-card-focus');
    }, 2000);
  }

  function buildPosterDeck(content, h2List) {
    if (content.querySelector('.cc-poster-deck')) return;
    if (!h2List || h2List.length === 0) return;

    var deck = document.createElement('div');
    deck.className = 'cc-poster-deck';

    var firstH2 = h2List[0];
    var parent = firstH2.parentNode;

    var sectionsData = [];
    for (var i = 0; i < h2List.length; i++) {
      var curH2 = h2List[i];
      var nextH2 = h2List[i + 1] || null;
      var nodes = [curH2];
      var sib = curH2.nextSibling;

      while (sib && sib !== nextH2) {
        var next = sib.nextSibling;
        if (sib.nodeType === 1 && sib.tagName.toLowerCase() === 'hr') {
          sib.parentNode.removeChild(sib);
        } else {
          nodes.push(sib);
        }
        sib = next;
      }
      sectionsData.push({ h2: curH2, nodes: nodes });
    }

    parent.insertBefore(deck, firstH2);

    sectionsData.forEach(function (sec, idx) {
      var card = document.createElement('section');
      card.className = 'cc-poster-card';
      var slug = sec.h2.id || ('sec-' + idx);
      card.setAttribute('data-section-id', slug);

      sec.nodes.forEach(function (n) {
        card.appendChild(n);
      });

      deck.appendChild(card);
    });
  }

  function determineSectionIcon(title) {
    var lower = title.toLowerCase();
    if (lower.indexOf('service') !== -1 || lower.indexOf('daemon') !== -1 || lower.indexOf('systemd') !== -1) return '⚡';
    if (lower.indexOf('log') !== -1 || lower.indexOf('journal') !== -1 || lower.indexOf('event') !== -1) return '📜';
    if (lower.indexOf('perf') !== -1 || lower.indexOf('cpu') !== -1 || lower.indexOf('memory') !== -1) return '📊';
    if (lower.indexOf('net') !== -1 || lower.indexOf('port') !== -1 || lower.indexOf('socket') !== -1) return '🌐';
    if (lower.indexOf('disk') !== -1 || lower.indexOf('storage') !== -1 || lower.indexOf('filesystem') !== -1) return '💾';
    if (lower.indexOf('user') !== -1 || lower.indexOf('active directory') !== -1 || lower.indexOf('identity') !== -1) return '👤';
    if (lower.indexOf('firewall') !== -1 || lower.indexOf('security') !== -1 || lower.indexOf('lock') !== -1) return '🛡️';
    if (lower.indexOf('emergency') !== -1 || lower.indexOf('triage') !== -1 || lower.indexOf('incident') !== -1) return '🚨';
    if (lower.indexOf('process') !== -1 || lower.indexOf('kill') !== -1) return '⚙️';
    return '📌';
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function escapeAttr(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHud);
  } else {
    initHud();
  }

  // MkDocs Material SPA page navigation subscription
  if (typeof app !== 'undefined' && app.document$) {
    app.document$.subscribe(initHud);
  }
})();
