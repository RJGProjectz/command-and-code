/**
 * Command & Code — Multi-Theme Switcher Engine
 * Supports 3 toggleable themes:
 *   1. classic        — Original calm, professional Field Manual (Slate / Amber)
 *   2. nexus-flow     — TemplateMo 594 Cyberpunk Neon (Deep Violet / Neon Cyan & Pink)
 *   3. electric-xtra   — TemplateMo 596 High-Voltage Sci-Fi (Obsidian / Electric Orange & Cyan)
 */

(function () {
  'use strict';

  var THEMES = [
    {
      id: 'classic',
      name: 'Classic',
      subtitle: 'Field Manual',
      icon: '🛡️',
      colors: ['#0f1318', '#c98a1a', '#5b7a99']
    },
    {
      id: 'nexus',
      name: 'Nexus',
      subtitle: 'Neon Synthwave',
      icon: '🔮',
      colors: ['#0f051a', '#00f3ff', '#ff007f']
    },
    {
      id: 'high-voltage',
      name: 'High Voltage',
      subtitle: 'Electric Grid',
      icon: '⚡',
      colors: ['#07090e', '#ff5e00', '#00b2ff']
    },
    {
      id: 'matrix',
      name: 'Matrix',
      subtitle: 'Digital Phosphor',
      icon: '🟢',
      colors: ['#030a05', '#00ff66', '#003b14']
    }
  ];

  var STORAGE_KEY = 'cc-theme';

  function getStoredTheme() {
    try {
      var saved = localStorage.getItem(STORAGE_KEY);
      if (saved === 'nexus-flow' || saved === 'nexus-cyber') return 'nexus';
      if (saved === 'electric-xtra' || saved === 'electric-cyber') return 'high-voltage';
      if (saved === 'matrix-green') return 'matrix';
      if (saved && (saved === 'classic' || saved === 'nexus' || saved === 'high-voltage' || saved === 'matrix')) {
        return saved;
      }
    } catch (e) {
      // localStorage not available
    }
    return 'classic';
  }

  function applyTheme(themeId) {
    document.documentElement.setAttribute('data-cc-theme', themeId);
    try {
      localStorage.setItem(STORAGE_KEY, themeId);
    } catch (e) {
      // ignore storage error
    }
    updateSwitcherUI(themeId);

    if (themeId === 'matrix' || themeId === 'matrix-green') {
      startMatrixCatRain();
    } else {
      stopMatrixCatRain();
    }
  }

  // Apply immediately on script load to prevent flicker
  var initialTheme = getStoredTheme();
  document.documentElement.setAttribute('data-cc-theme', initialTheme);

  function createSwitcherElement() {
    var container = document.createElement('div');
    container.className = 'cc-theme-switcher';
    container.setAttribute('role', 'region');
    container.setAttribute('aria-label', 'Theme Selector');

    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'cc-theme-switcher-btn';
    button.setAttribute('aria-expanded', 'false');
    button.setAttribute('aria-haspopup', 'true');
    button.innerHTML = [
      '<span class="cc-theme-icon">🎨</span>',
      '<span class="cc-theme-prefix">Themes:</span>',
      '<span class="cc-theme-current-label">Classic</span>',
      '<svg class="cc-theme-chevron" viewBox="0 0 24 24" width="14" height="14">',
      '  <path fill="currentColor" d="M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6 1.41-1.41z"/>',
      '</svg>'
    ].join('');

    var menu = document.createElement('div');
    menu.className = 'cc-theme-menu';
    menu.setAttribute('role', 'menu');

    THEMES.forEach(function (theme) {
      var item = document.createElement('button');
      item.type = 'button';
      item.className = 'cc-theme-option';
      item.setAttribute('role', 'menuitem');
      item.setAttribute('data-theme-id', theme.id);

      var swatchesHtml = theme.colors.map(function (c) {
        return '<span class="cc-swatch" style="background-color: ' + c + '"></span>';
      }).join('');

      item.innerHTML = [
        '<div class="cc-option-info">',
        '  <span class="cc-option-icon">' + theme.icon + '</span>',
        '  <div class="cc-option-text">',
        '    <span class="cc-option-name">' + theme.name + '</span>',
        '    <span class="cc-option-desc">' + theme.subtitle + '</span>',
        '  </div>',
        '</div>',
        '<div class="cc-option-meta">',
        '  <div class="cc-swatches">' + swatchesHtml + '</div>',
        '  <span class="cc-check-mark">✓</span>',
        '</div>'
      ].join('');

      item.addEventListener('click', function (e) {
        e.stopPropagation();
        applyTheme(theme.id);
        closeMenu();
      });

      menu.appendChild(item);
    });

    button.addEventListener('click', function (e) {
      e.stopPropagation();
      var isExpanded = button.getAttribute('aria-expanded') === 'true';
      if (isExpanded) {
        closeMenu();
      } else {
        openMenu();
      }
    });

    document.addEventListener('click', function (e) {
      if (!container.contains(e.target)) {
        closeMenu();
      }
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        closeMenu();
      }
    });

    function openMenu() {
      button.setAttribute('aria-expanded', 'true');
      menu.classList.add('cc-menu-open');
    }

    function closeMenu() {
      button.setAttribute('aria-expanded', 'false');
      menu.classList.remove('cc-menu-open');
    }

    container.appendChild(button);
    container.appendChild(menu);
    return container;
  }

  function updateSwitcherUI(activeThemeId) {
    var cur = THEMES.find(function (t) { return t.id === activeThemeId; }) || THEMES[0];
    var labels = document.querySelectorAll('.cc-theme-current-label');
    labels.forEach(function (el) {
      el.textContent = cur.name;
    });

    var icons = document.querySelectorAll('.cc-theme-icon');
    icons.forEach(function (el) {
      el.textContent = cur.icon;
    });

    var options = document.querySelectorAll('.cc-theme-option');
    options.forEach(function (opt) {
      var id = opt.getAttribute('data-theme-id');
      if (id === activeThemeId) {
        opt.classList.add('cc-option-active');
      } else {
        opt.classList.remove('cc-option-active');
      }
    });
  }

  function mountSwitcher() {
    if (document.querySelector('.cc-theme-switcher')) {
      return;
    }

    var switcher = createSwitcherElement();

    // Prefer header placement: right inside .md-header__inner
    var headerInner = document.querySelector('.md-header__inner');
    if (headerInner) {
      // Insert before search or repo link
      var repo = headerInner.querySelector('.md-header__source');
      if (repo) {
        headerInner.insertBefore(switcher, repo);
      } else {
        headerInner.appendChild(switcher);
      }
    } else {
      // Fallback: floating widget
      switcher.classList.add('cc-switcher-floating');
      document.body.appendChild(switcher);
    }

    updateSwitcherUI(getStoredTheme());
    checkAndInitMatrix();
  }

  // =========================================================================
  // Matrix Cat Rain Engine (Pseudo Matrix Rainfall with Falling ASCII Cats)
  // =========================================================================
  var CAT_ASCII = [
    '(=^･ω･^=)',
    'ฅ^•ﻌ•^ฅ',
    '(=^･^=)',
    '(=^-ω-^=)',
    '(^._.^)ﾉ',
    'ฅ/ᐠ. ̫ .ᐟ\\ฅ',
    '(=`ω´=)',
    '(=^‥^=)',
    'ﾐ^._.^ﾐ',
    '(=ｘェｘ=)',
    '(=ΦｴΦ=)',
    '~(=^‥^)',
    '(=;ェ;=)',
    'ฅ(≈>ܫ<≈)ฅ',
    '(=^･ｪ･^=)',
    '(^・x・^)',
    '(=^-人-^=)',
    'ᓚᘏᗢ',
    '/\\_/\\',
    '( o.o )',
    '> ^ <',
    '/\\___/\\',
    "( ='.'= )",
    '(")_(")',
    '(\\__/)',
    '( •x• )',
    'c[_]',
    '🐾',
    '🐾🐾',
    'MEOW',
    'NYA~',
    'PURR',
    'CATRIX',
    ':3',
    'ฅ',
    '^._.^'
  ];

  var MULTI_CATS = [
    ['/\\_/\\', '( o.o )', '> ^ <'],
    ['/\\___/\\', "( ='.'= )", '(")_(")'],
    ['(\\__/)', '( •x• )', '(")_(")'],
    ['/\\_/\\', '(=^.^=)', '(")_(")']
  ];

  var catCanvas = null;
  var catCtx = null;
  var rainFrameId = null;
  var rainColumns = [];
  var lastRainTick = 0;
  var RAIN_TICK_INTERVAL = 44; // ms between rainfall steps (~23 fps)

  function getOrCreateCatCanvas() {
    if (!catCanvas) {
      catCanvas = document.getElementById('cc-matrix-cat-canvas');
      if (!catCanvas) {
        catCanvas = document.createElement('canvas');
        catCanvas.id = 'cc-matrix-cat-canvas';
        catCanvas.className = 'cc-matrix-cat-canvas';
        catCanvas.setAttribute('aria-hidden', 'true');
        document.body.appendChild(catCanvas);
      }
      catCtx = catCanvas.getContext('2d');
    }
    return catCanvas;
  }

  function resizeCatCanvas() {
    if (!catCanvas) return;
    var w = window.innerWidth || document.documentElement.clientWidth || 800;
    var h = window.innerHeight || document.documentElement.clientHeight || 600;
    catCanvas.width = w;
    catCanvas.height = h;

    // Reset columns: spacing ~48px
    var colWidth = 48;
    var numCols = Math.max(10, Math.floor(w / colWidth));
    rainColumns = [];
    for (var i = 0; i < numCols; i++) {
      rainColumns.push({
        x: i * colWidth + colWidth / 2,
        y: Math.floor(Math.random() * -30),
        sequence: null,
        seqIndex: 0
      });
    }

    if (catCtx) {
      catCtx.fillStyle = '#020704';
      catCtx.fillRect(0, 0, w, h);
    }
  }

  function stepMatrixCatRain(now) {
    if (!rainFrameId) return;

    if (!now || now - lastRainTick >= RAIN_TICK_INTERVAL) {
      lastRainTick = now;

      var w = catCanvas.width;
      var h = catCanvas.height;

      // Dark translucent wash to create authentic Matrix trailing fade
      catCtx.fillStyle = 'rgba(2, 7, 4, 0.085)';
      catCtx.fillRect(0, 0, w, h);

      catCtx.font = '13px monospace';
      catCtx.textAlign = 'center';

      for (var i = 0; i < rainColumns.length; i++) {
        var col = rainColumns[i];
        var yPos = col.y * 22;

        var token;
        if (col.sequence) {
          token = col.sequence[col.seqIndex++];
          if (col.seqIndex >= col.sequence.length) {
            col.sequence = null;
          }
        } else {
          if (Math.random() < 0.08) {
            col.sequence = MULTI_CATS[Math.floor(Math.random() * MULTI_CATS.length)];
            col.seqIndex = 0;
            token = col.sequence[col.seqIndex++];
          } else {
            token = CAT_ASCII[Math.floor(Math.random() * CAT_ASCII.length)];
          }
        }

        if (yPos >= -10 && yPos <= h + 30) {
          // Glow head in radiant white-mint phosphor
          catCtx.fillStyle = '#f0fdf4';
          catCtx.shadowColor = '#00ff66';
          catCtx.shadowBlur = 9;
          catCtx.fillText(token, col.x, yPos);
          catCtx.shadowBlur = 0;
        }

        col.y++;

        // Reset column when it passes bottom with randomized stagger
        if (yPos > h + 30 && Math.random() > 0.95) {
          col.y = Math.floor(Math.random() * -15);
        }
      }
    }

    rainFrameId = requestAnimationFrame(stepMatrixCatRain);
  }

  function startMatrixCatRain() {
    getOrCreateCatCanvas();
    if (!catCanvas || !catCtx) return;

    if (!rainColumns.length || catCanvas.width !== window.innerWidth) {
      resizeCatCanvas();
    }

    if (!rainFrameId) {
      lastRainTick = 0;
      rainFrameId = requestAnimationFrame(stepMatrixCatRain);
    }
  }

  function stopMatrixCatRain() {
    if (rainFrameId) {
      cancelAnimationFrame(rainFrameId);
      rainFrameId = null;
    }
    if (catCtx && catCanvas) {
      catCtx.clearRect(0, 0, catCanvas.width, catCanvas.height);
    }
  }

  window.addEventListener('resize', function () {
    if (rainFrameId) {
      resizeCatCanvas();
    }
  });

  function checkAndInitMatrix() {
    var current = getStoredTheme();
    if (current === 'matrix' || current === 'matrix-green') {
      startMatrixCatRain();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountSwitcher);
  } else {
    mountSwitcher();
  }

  // Handle Material for MkDocs instant navigation (pjax)
  if (typeof window !== 'undefined' && 'MutationObserver' in window) {
    var observer = new MutationObserver(function () {
      if (!document.querySelector('.cc-theme-switcher')) {
        mountSwitcher();
      }
      checkAndInitMatrix();
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }
})();
