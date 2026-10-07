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
      id: 'catrix',
      name: 'Catrix',
      subtitle: 'Digital Phosphor Cats',
      icon: '🐾',
      colors: ['#030a05', '#00ff66', '#003b14']
    },
    {
      id: 'crimson',
      name: 'Crimson Alert',
      subtitle: 'SOC War Room',
      icon: '🚨',
      colors: ['#080406', '#ff1744', '#ff9100']
    }
  ];

  var STORAGE_KEY = 'cc-theme';

  function getStoredTheme() {
    try {
      var saved = localStorage.getItem(STORAGE_KEY);
      if (saved === 'nexus-flow' || saved === 'nexus-cyber') return 'nexus';
      if (saved === 'electric-xtra' || saved === 'electric-cyber') return 'high-voltage';
      if (saved === 'matrix' || saved === 'matrix-green') return 'catrix';
      if (saved === 'crimson-alert' || saved === 'war-room' || saved === 'red-cell') return 'crimson';
      if (saved && (saved === 'classic' || saved === 'nexus' || saved === 'high-voltage' || saved === 'catrix' || saved === 'crimson')) {
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

    if (themeId === 'nexus' || themeId === 'nexus-cyber' || themeId === 'nexus-flow') {
      randomizeNexusGradient();
    }

    if (themeId === 'catrix' || themeId === 'matrix' || themeId === 'matrix-green') {
      startMatrixCatRain();
    } else {
      stopMatrixCatRain();
    }

    if (themeId === 'high-voltage' || themeId === 'electric-cyber' || themeId === 'electric-xtra') {
      startElectricTrace();
    } else {
      stopElectricTrace();
    }
  }

  // =========================================================================
  // Nexus Procedural Gradient Randomizer (Static on view, varied per refresh)
  // =========================================================================
  function randomizeNexusGradient() {
    var root = document.documentElement;
    // Slanted cyber linear mesh angle: 120deg - 155deg or 35deg - 65deg
    var angle = Math.random() < 0.5
      ? Math.floor(120 + Math.random() * 35) + 'deg'
      : Math.floor(35 + Math.random() * 30) + 'deg';
    var mid = Math.floor(44 + Math.random() * 14) + '%';

    // Jitter neon glow centers across viewport quadrants
    var cx1 = Math.floor(14 + Math.random() * 18) + '%'; // Cyan upper flare
    var cy1 = Math.floor(12 + Math.random() * 16) + '%';
    var cx2 = Math.floor(74 + Math.random() * 16) + '%'; // Pink lower flare
    var cy2 = Math.floor(74 + Math.random() * 16) + '%';
    var cx3 = Math.floor(46 + Math.random() * 14) + '%'; // Purple core
    var cy3 = Math.floor(44 + Math.random() * 14) + '%';
    var cx4 = Math.floor(78 + Math.random() * 14) + '%'; // Cyan top-right accent
    var cy4 = Math.floor(10 + Math.random() * 12) + '%';
    var cx5 = Math.floor(12 + Math.random() * 14) + '%'; // Violet bottom-left accent
    var cy5 = Math.floor(80 + Math.random() * 12) + '%';

    // Subtle luminous opacity variations per session
    var op1 = (0.13 + Math.random() * 0.06).toFixed(3);
    var op2 = (0.13 + Math.random() * 0.06).toFixed(3);
    var op3 = (0.18 + Math.random() * 0.06).toFixed(3);
    var op4 = (0.07 + Math.random() * 0.05).toFixed(3);
    var op5 = (0.09 + Math.random() * 0.05).toFixed(3);

    root.style.setProperty('--cc-nexus-angle', angle);
    root.style.setProperty('--cc-nexus-mid', mid);
    root.style.setProperty('--cc-nexus-cx1', cx1);
    root.style.setProperty('--cc-nexus-cy1', cy1);
    root.style.setProperty('--cc-nexus-cx2', cx2);
    root.style.setProperty('--cc-nexus-cy2', cy2);
    root.style.setProperty('--cc-nexus-cx3', cx3);
    root.style.setProperty('--cc-nexus-cy3', cy3);
    root.style.setProperty('--cc-nexus-cx4', cx4);
    root.style.setProperty('--cc-nexus-cy4', cy4);
    root.style.setProperty('--cc-nexus-cx5', cx5);
    root.style.setProperty('--cc-nexus-cy5', cy5);
    root.style.setProperty('--cc-nexus-op1', op1);
    root.style.setProperty('--cc-nexus-op2', op2);
    root.style.setProperty('--cc-nexus-op3', op3);
    root.style.setProperty('--cc-nexus-op4', op4);
    root.style.setProperty('--cc-nexus-op5', op5);
  }

  // Apply immediately on script load to prevent flicker
  var initialTheme = getStoredTheme();
  document.documentElement.setAttribute('data-cc-theme', initialTheme);
  if (initialTheme === 'nexus' || initialTheme === 'nexus-cyber' || initialTheme === 'nexus-flow') {
    randomizeNexusGradient();
  }

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
    checkAndInitActiveThemeEffects();
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

  // =========================================================================
  // High Voltage Electrical Trace Engine (Single Wandering Circuit Spark)
  // =========================================================================
  var sparkCanvas = null;
  var sparkCtx = null;
  var sparkFrameId = null;

  var SPARK_GRID = 50; // Aligns 1:1 with CSS background-size: 50px 50px
  var SPARK_SPEED = 3.5; // Pixels per frame
  var SPARK_TRAIL_LENGTH = 32; // Number of historical trail segments

  // Spark state
  var spark = {
    x: 0,
    y: 0,
    currGridX: 0,
    currGridY: 0,
    nextGridX: 0,
    nextGridY: 0,
    destGridX: 0,
    destGridY: 0,
    dx: 0,
    dy: 0,
    trail: [],
    particles: []
  };

  function getOrCreateSparkCanvas() {
    if (sparkCanvas && document.body.contains(sparkCanvas)) {
      return;
    }
    sparkCanvas = document.querySelector('.cc-electric-spark-canvas');
    if (!sparkCanvas) {
      sparkCanvas = document.createElement('canvas');
      sparkCanvas.className = 'cc-electric-spark-canvas';
      sparkCanvas.setAttribute('aria-hidden', 'true');
      document.body.appendChild(sparkCanvas);
    }
    sparkCtx = sparkCanvas.getContext('2d');
  }

  function resizeSparkCanvas() {
    if (!sparkCanvas) return;
    sparkCanvas.width = window.innerWidth;
    sparkCanvas.height = window.innerHeight;
  }

  function getRandomGridPoint(w, h) {
    var cols = Math.max(2, Math.floor(w / SPARK_GRID));
    var rows = Math.max(2, Math.floor(h / SPARK_GRID));
    var gx = Math.floor(Math.random() * cols) * SPARK_GRID;
    var gy = Math.floor(Math.random() * rows) * SPARK_GRID;
    return { x: gx, y: gy };
  }

  function initSparkState() {
    var w = window.innerWidth || 1200;
    var h = window.innerHeight || 800;

    var start = getRandomGridPoint(w, h);
    var end = getRandomGridPoint(w, h);
    while (end.x === start.x && end.y === start.y) {
      end = getRandomGridPoint(w, h);
    }

    spark.x = start.x;
    spark.y = start.y;
    spark.currGridX = start.x;
    spark.currGridY = start.y;
    spark.destGridX = end.x;
    spark.destGridY = end.y;
    spark.trail = [{ x: start.x, y: start.y }];
    spark.particles = [];

    chooseNextGridStep();
  }

  function chooseNextGridStep() {
    var currX = spark.currGridX;
    var currY = spark.currGridY;
    var destX = spark.destGridX;
    var destY = spark.destGridY;

    var w = window.innerWidth || 1200;
    var h = window.innerHeight || 800;

    if (currX === destX && currY === destY) {
      createSparkBurst(currX, currY);
      var newDest = getRandomGridPoint(w, h);
      spark.destGridX = newDest.x;
      spark.destGridY = newDest.y;
      destX = newDest.x;
      destY = newDest.y;
    }

    var options = [
      { gx: currX + SPARK_GRID, gy: currY, dx: 1, dy: 0 },
      { gx: currX - SPARK_GRID, gy: currY, dx: -1, dy: 0 },
      { gx: currX, gy: currY + SPARK_GRID, dx: 0, dy: 1 },
      { gx: currX, gy: currY - SPARK_GRID, dx: 0, dy: -1 }
    ];

    var valid = options.filter(function (opt) {
      return opt.gx >= 0 && opt.gx <= w + SPARK_GRID && opt.gy >= 0 && opt.gy <= h + SPARK_GRID;
    });

    if (!valid.length) {
      valid = options;
    }

    if (valid.length > 1 && (spark.dx !== 0 || spark.dy !== 0)) {
      var filtered = valid.filter(function (opt) {
        return !(opt.dx === -spark.dx && opt.dy === -spark.dy);
      });
      if (filtered.length) {
        valid = filtered;
      }
    }

    var currentDist = Math.abs(destX - currX) + Math.abs(destY - currY);
    var pool = [];

    valid.forEach(function (opt) {
      var dist = Math.abs(destX - opt.gx) + Math.abs(destY - opt.gy);
      if (dist < currentDist) {
        pool.push(opt, opt, opt, opt);
      } else {
        pool.push(opt);
      }
    });

    var chosen = pool[Math.floor(Math.random() * pool.length)] || valid[0];
    spark.nextGridX = chosen.gx;
    spark.nextGridY = chosen.gy;
    spark.dx = chosen.dx;
    spark.dy = chosen.dy;
  }

  function createSparkBurst(x, y) {
    for (var i = 0; i < 8; i++) {
      var angle = Math.random() * Math.PI * 2;
      var speed = 1.2 + Math.random() * 2.5;
      spark.particles.push({
        x: x,
        y: y,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        life: 1.0,
        decay: 0.04 + Math.random() * 0.04
      });
    }
  }

  function stepElectricTrace() {
    if (!sparkCanvas || !sparkCtx) return;

    var w = sparkCanvas.width;
    var h = sparkCanvas.height;

    sparkCtx.clearRect(0, 0, w, h);

    var toNextX = spark.nextGridX - spark.x;
    var toNextY = spark.nextGridY - spark.y;
    var dist = Math.hypot(toNextX, toNextY);

    if (dist <= SPARK_SPEED) {
      spark.x = spark.nextGridX;
      spark.y = spark.nextGridY;
      spark.currGridX = spark.nextGridX;
      spark.currGridY = spark.nextGridY;
      chooseNextGridStep();
    } else {
      spark.x += spark.dx * SPARK_SPEED;
      spark.y += spark.dy * SPARK_SPEED;
    }

    spark.trail.push({ x: spark.x, y: spark.y });
    if (spark.trail.length > SPARK_TRAIL_LENGTH) {
      spark.trail.shift();
    }

    // Draw trail (neon light blue gradient fade)
    if (spark.trail.length > 1) {
      for (var i = 1; i < spark.trail.length; i++) {
        var pPrev = spark.trail[i - 1];
        var pCurr = spark.trail[i];
        var progress = i / spark.trail.length;
        var alpha = progress * progress * 0.95;
        var lineWidth = 1.0 + progress * 2.5;

        sparkCtx.beginPath();
        sparkCtx.moveTo(pPrev.x, pPrev.y);
        sparkCtx.lineTo(pCurr.x, pCurr.y);
        sparkCtx.strokeStyle = 'rgba(56, 189, 248, ' + alpha + ')'; // Neon light blue
        sparkCtx.lineWidth = lineWidth;
        sparkCtx.lineCap = 'round';
        sparkCtx.shadowColor = '#00f3ff';
        sparkCtx.shadowBlur = 8 * progress;
        sparkCtx.stroke();
      }
    }

    // Draw spark head
    var headX = spark.x;
    var headY = spark.y;

    sparkCtx.save();
    sparkCtx.beginPath();
    sparkCtx.arc(headX, headY, 5, 0, Math.PI * 2);
    sparkCtx.fillStyle = 'rgba(0, 243, 255, 0.4)';
    sparkCtx.shadowColor = '#00f3ff';
    sparkCtx.shadowBlur = 18;
    sparkCtx.fill();

    sparkCtx.beginPath();
    sparkCtx.arc(headX, headY, 2.5, 0, Math.PI * 2);
    sparkCtx.fillStyle = '#ffffff';
    sparkCtx.shadowColor = '#38bdf8';
    sparkCtx.shadowBlur = 10;
    sparkCtx.fill();

    if (Math.random() < 0.6) {
      var arcAngle = Math.random() * Math.PI * 2;
      var arcLen = 3 + Math.random() * 5;
      sparkCtx.beginPath();
      sparkCtx.moveTo(headX, headY);
      sparkCtx.lineTo(headX + Math.cos(arcAngle) * arcLen, headY + Math.sin(arcAngle) * arcLen);
      sparkCtx.strokeStyle = '#e0f2fe';
      sparkCtx.lineWidth = 1.5;
      sparkCtx.shadowColor = '#00f3ff';
      sparkCtx.shadowBlur = 6;
      sparkCtx.stroke();
    }
    sparkCtx.restore();

    // Draw burst particles
    for (var j = spark.particles.length - 1; j >= 0; j--) {
      var pt = spark.particles[j];
      pt.x += pt.vx;
      pt.y += pt.vy;
      pt.life -= pt.decay;

      if (pt.life <= 0) {
        spark.particles.splice(j, 1);
      } else {
        sparkCtx.save();
        sparkCtx.beginPath();
        sparkCtx.arc(pt.x, pt.y, 1.8 * pt.life, 0, Math.PI * 2);
        sparkCtx.fillStyle = 'rgba(0, 243, 255, ' + pt.life + ')';
        sparkCtx.shadowColor = '#00f3ff';
        sparkCtx.shadowBlur = 8;
        sparkCtx.fill();
        sparkCtx.restore();
      }
    }

    sparkFrameId = requestAnimationFrame(stepElectricTrace);
  }

  function startElectricTrace() {
    getOrCreateSparkCanvas();
    if (!sparkCanvas || !sparkCtx) return;

    if (sparkCanvas.width !== window.innerWidth || sparkCanvas.height !== window.innerHeight) {
      resizeSparkCanvas();
    }

    if (!sparkFrameId) {
      initSparkState();
      sparkFrameId = requestAnimationFrame(stepElectricTrace);
    }
  }

  function stopElectricTrace() {
    if (sparkFrameId) {
      cancelAnimationFrame(sparkFrameId);
      sparkFrameId = null;
    }
    if (sparkCtx && sparkCanvas) {
      sparkCtx.clearRect(0, 0, sparkCanvas.width, sparkCanvas.height);
    }
  }

  window.addEventListener('resize', function () {
    if (rainFrameId) {
      resizeCatCanvas();
    }
    if (sparkFrameId) {
      resizeSparkCanvas();
    }
  });

  function checkAndInitActiveThemeEffects() {
    var current = getStoredTheme();
    if (current === 'nexus' || current === 'nexus-cyber' || current === 'nexus-flow') {
      randomizeNexusGradient();
    }
    if (current === 'catrix' || current === 'matrix' || current === 'matrix-green') {
      startMatrixCatRain();
    }
    if (current === 'high-voltage' || current === 'electric-cyber' || current === 'electric-xtra') {
      startElectricTrace();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountSwitcher);
  } else {
    mountSwitcher();
  }

  // Handle Material for MkDocs instant navigation (pjax / instant loading)
  if (typeof app !== 'undefined' && app.document$) {
    app.document$.subscribe(function () {
      mountSwitcher();
      checkAndInitActiveThemeEffects();
    });
  } else if (typeof window !== 'undefined' && 'MutationObserver' in window) {
    var observer = new MutationObserver(function () {
      if (!document.querySelector('.cc-theme-switcher')) {
        mountSwitcher();
      }
      checkAndInitActiveThemeEffects();
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }
})();
