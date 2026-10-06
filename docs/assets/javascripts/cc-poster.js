/**
 * Command & Code — Interactive Command & Syntax Poster Wall Engine
 * Transforms static cheat sheets into rich, interactive command poster decks
 * with live filtering, instant one-click copy, and real-time parameter injection.
 */
(function () {
  'use strict';

  function isCheatSheetPage() {
    var p = window.location.pathname.toLowerCase();
    return p.indexOf('cheat-sheet') !== -1 || document.querySelector('.cc-interactive-poster');
  }

  function initPoster() {
    if (!isCheatSheetPage()) return;

    var content = document.querySelector('.md-content__inner');
    if (!content) return;

    // Avoid double initialization
    if (content.querySelector('.cc-poster-deck')) return;

    // Parse commands and sections from the markdown DOM
    var sections = [];
    var currentSection = null;
    var rawNodes = Array.from(content.children);

    var h2Elements = content.querySelectorAll('h2');
    if (h2Elements.length === 0) return;

    // Extract categories, commands, and code blocks
    rawNodes.forEach(function (node) {
      if (node.tagName === 'H2') {
        var title = node.textContent.replace(/^[0-9.]+\s*/, '').trim();
        // Skip 'Related' or 'Sources' sections from poster grid
        if (title.toLowerCase().indexOf('related') !== -1 || title.toLowerCase().indexOf('sources') !== -1) {
          currentSection = null;
          return;
        }
        currentSection = {
          name: title,
          tiles: []
        };
        sections.push(currentSection);
      } else if (currentSection) {
        if (node.tagName === 'PRE' || node.classList.contains('highlight')) {
          var codeEl = node.querySelector('code');
          if (codeEl) {
            var rawText = codeEl.textContent;
            var parsedTiles = parseCodeBlockIntoTiles(rawText, currentSection.name);
            currentSection.tiles = currentSection.tiles.concat(parsedTiles);
          }
        } else if (node.tagName === 'TABLE') {
          // Parse table comparison rows into poster tiles
          var rows = node.querySelectorAll('tbody tr');
          rows.forEach(function (tr) {
            var cells = Array.from(tr.querySelectorAll('td'));
            if (cells.length >= 2) {
              var obj = cells[0].textContent.trim();
              for (var i = 1; i < cells.length; i++) {
                var codeTag = cells[i].querySelector('code');
                var cmdText = codeTag ? codeTag.textContent : cells[i].textContent.trim();
                if (cmdText) {
                  currentSection.tiles.push({
                    category: currentSection.name,
                    title: obj,
                    command: cmdText,
                    badge: determineBadge(cmdText, obj),
                    flags: extractFlags(cmdText)
                  });
                }
              }
            }
          });
        }
      }
    });

    var allTiles = [];
    sections.forEach(function (sec) {
      allTiles = allTiles.concat(sec.tiles);
    });

    if (allTiles.length === 0) return;

    // Create the Interactive Poster Container
    var deckContainer = document.createElement('div');
    deckContainer.className = 'cc-poster-deck';

    // Top Toolbar
    var toolbar = document.createElement('div');
    toolbar.className = 'cc-poster-toolbar';

    // View Mode Toggle (Poster Wall vs Document View)
    var toggleWrap = document.createElement('div');
    toggleWrap.className = 'cc-poster-view-toggle';
    toggleWrap.innerHTML =
      '<button class="cc-poster-toggle-btn cc-active" data-view="poster" title="Interactive Bento Poster View">▦ Poster Grid</button>' +
      '<button class="cc-poster-toggle-btn" data-view="doc" title="Standard Markdown Manual View">📄 Linear Doc</button>';

    // Live Search Input
    var searchBox = document.createElement('div');
    searchBox.className = 'cc-poster-search-box';
    searchBox.innerHTML =
      '<span class="cc-poster-search-icon">🔍</span>' +
      '<input type="text" class="cc-poster-search-input" placeholder="Live filter commands (e.g. systemctl, journalctl, pkill)..." aria-label="Filter commands">';

    toolbar.appendChild(toggleWrap);
    toolbar.appendChild(searchBox);
    deckContainer.appendChild(toolbar);

    // Filter Chips
    var filterBar = document.createElement('div');
    filterBar.className = 'cc-poster-filter-bar';

    var allChip = document.createElement('button');
    allChip.className = 'cc-poster-filter-chip cc-active';
    allChip.setAttribute('data-category', 'all');
    allChip.innerHTML = 'All Commands <span class="cc-poster-filter-count">' + allTiles.length + '</span>';
    filterBar.appendChild(allChip);

    sections.forEach(function (sec) {
      if (sec.tiles.length === 0) return;
      var chip = document.createElement('button');
      chip.className = 'cc-poster-filter-chip';
      chip.setAttribute('data-category', sec.name);
      chip.innerHTML = sec.name + ' <span class="cc-poster-filter-count">' + sec.tiles.length + '</span>';
      filterBar.appendChild(chip);
    });
    deckContainer.appendChild(filterBar);

    // Live Parameter Customizer Strip
    var paramStrip = document.createElement('div');
    paramStrip.className = 'cc-poster-param-strip';
    paramStrip.innerHTML =
      '<div class="cc-poster-param-label">⚡ Live Parameter Injection:</div>' +
      '<div class="cc-poster-param-fields">' +
        '<div class="cc-poster-param-group"><label>User:</label><input type="text" class="cc-poster-param-input" data-param="USER" value="admin"></div>' +
        '<div class="cc-poster-param-group"><label>Service:</label><input type="text" class="cc-poster-param-input" data-param="SERVICE" value="nginx"></div>' +
        '<div class="cc-poster-param-group"><label>Host:</label><input type="text" class="cc-poster-param-input" data-param="HOST" value="srv-app-01"></div>' +
      '</div>';
    deckContainer.appendChild(paramStrip);

    // Bento Poster Wall Grid
    var wall = document.createElement('div');
    wall.className = 'cc-poster-wall';

    allTiles.forEach(function (tile, idx) {
      var tileEl = document.createElement('div');
      tileEl.className = 'cc-poster-tile';
      tileEl.setAttribute('data-category', tile.category);
      tileEl.setAttribute('data-index', idx);

      var flagsHtml = '';
      if (tile.flags && tile.flags.length > 0) {
        flagsHtml = '<div class="cc-poster-explainer-bar">' +
          tile.flags.map(function (f) {
            return '<span class="cc-poster-pill"><strong>' + escapeHtml(f.flag) + '</strong> ' + escapeHtml(f.desc) + '</span>';
          }).join('') +
          '</div>';
      }

      tileEl.innerHTML =
        '<div>' +
          '<div class="cc-poster-tile-top">' +
            '<span class="cc-poster-category-tag">' + escapeHtml(tile.category) + '</span>' +
            '<span class="cc-poster-badge cc-badge-' + tile.badge.type + '">' + escapeHtml(tile.badge.label) + '</span>' +
          '</div>' +
          '<div class="cc-poster-tile-title">' + escapeHtml(tile.title) + '</div>' +
          '<div class="cc-poster-code-wrap">' +
            '<code class="cc-poster-code-text" data-original="' + escapeAttr(tile.command) + '">' + escapeHtml(tile.command) + '</code>' +
            '<button class="cc-poster-copy-btn" title="Copy command to clipboard">' +
              '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg>' +
            '</button>' +
          '</div>' +
        '</div>' +
        flagsHtml;

      wall.appendChild(tileEl);
    });

    deckContainer.appendChild(wall);

    // Insert deck at top of content (after h1 and meta)
    var h1 = content.querySelector('h1');
    var metaStrip = content.querySelector('.cc-meta') || content.querySelector('.cc-aliases');
    var insertTarget = metaStrip ? metaStrip.nextSibling : (h1 ? h1.nextSibling : content.firstChild);
    content.insertBefore(deckContainer, insertTarget);

    // Identify standard document blocks to toggle visibility
    var docElements = [];
    var sibling = deckContainer.nextSibling;
    while (sibling) {
      if (sibling.nodeType === 1) {
        docElements.push(sibling);
      }
      sibling = sibling.nextSibling;
    }

    // Default to Poster Grid View
    function applyView(mode) {
      if (mode === 'doc') {
        wall.classList.add('cc-doc-hidden');
        paramStrip.classList.add('cc-doc-hidden');
        filterBar.classList.add('cc-doc-hidden');
        docElements.forEach(function (el) { el.classList.remove('cc-doc-hidden'); });
        toggleWrap.querySelector('[data-view="poster"]').classList.remove('cc-active');
        toggleWrap.querySelector('[data-view="doc"]').classList.add('cc-active');
      } else {
        wall.classList.remove('cc-doc-hidden');
        paramStrip.classList.remove('cc-doc-hidden');
        filterBar.classList.remove('cc-doc-hidden');
        docElements.forEach(function (el) { el.classList.add('cc-doc-hidden'); });
        toggleWrap.querySelector('[data-view="poster"]').classList.add('cc-active');
        toggleWrap.querySelector('[data-view="doc"]').classList.remove('cc-active');
      }
    }

    applyView('poster');

    // View toggle event listeners
    toggleWrap.querySelectorAll('.cc-poster-toggle-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var view = this.getAttribute('data-view');
        applyView(view);
      });
    });

    // Category filter event listeners
    filterBar.querySelectorAll('.cc-poster-filter-chip').forEach(function (chip) {
      chip.addEventListener('click', function () {
        filterBar.querySelectorAll('.cc-poster-filter-chip').forEach(function (c) { c.classList.remove('cc-active'); });
        this.classList.add('cc-active');
        filterTiles();
      });
    });

    // Search input listener
    var searchInput = searchBox.querySelector('.cc-poster-search-input');
    searchInput.addEventListener('input', function () {
      filterTiles();
    });

    function filterTiles() {
      var activeCat = filterBar.querySelector('.cc-poster-filter-chip.cc-active').getAttribute('data-category');
      var q = searchInput.value.toLowerCase().trim();

      wall.querySelectorAll('.cc-poster-tile').forEach(function (tile) {
        var cat = tile.getAttribute('data-category');
        var text = tile.textContent.toLowerCase();

        var matchesCat = (activeCat === 'all' || cat === activeCat);
        var matchesQuery = (q === '' || text.indexOf(q) !== -1);

        if (matchesCat && matchesQuery) {
          tile.classList.remove('cc-tile-hidden');
        } else {
          tile.classList.add('cc-tile-hidden');
        }
      });
    }

    // Parameter live injection listener
    var paramInputs = paramStrip.querySelectorAll('.cc-poster-param-input');
    function updateParameters() {
      var userVal = paramStrip.querySelector('[data-param="USER"]').value || 'admin';
      var servVal = paramStrip.querySelector('[data-param="SERVICE"]').value || 'nginx';
      var hostVal = paramStrip.querySelector('[data-param="HOST"]').value || 'srv-app-01';

      wall.querySelectorAll('.cc-poster-code-text').forEach(function (code) {
        var orig = code.getAttribute('data-original');
        var replaced = orig
          .replace(/<USER>/g, userVal)
          .replace(/<service_name>/g, servVal)
          .replace(/<TARGET_HOST>/g, hostVal)
          .replace(/<ADMIN_USER>/g, userVal);
        code.textContent = replaced;
      });
    }

    paramInputs.forEach(function (inp) {
      inp.addEventListener('input', updateParameters);
    });
    updateParameters();

    // Quick Copy button handlers
    wall.querySelectorAll('.cc-poster-copy-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var codeEl = this.parentElement.querySelector('.cc-poster-code-text');
        var textToCopy = codeEl ? codeEl.textContent : '';

        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(textToCopy).then(function () {
            showCopiedState(btn);
          }).catch(function () {
            fallbackCopy(textToCopy, btn);
          });
        } else {
          fallbackCopy(textToCopy, btn);
        }
      });
    });

    function showCopiedState(btn) {
      btn.classList.add('cc-copied');
      btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>';
      setTimeout(function () {
        btn.classList.remove('cc-copied');
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg>';
      }, 1800);
    }

    function fallbackCopy(text, btn) {
      var textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand('copy');
        showCopiedState(btn);
      } catch (e) {}
      document.body.removeChild(textarea);
    }
  }

  function parseCodeBlockIntoTiles(rawText, category) {
    var tiles = [];
    var lines = rawText.split(/\r?\n/);
    var currentComment = '';
    var currentCommandLines = [];

    lines.forEach(function (line) {
      var trimmed = line.trim();
      if (!trimmed) {
        if (currentCommandLines.length > 0) {
          tiles.push(createTileObj(category, currentComment, currentCommandLines.join('\n')));
          currentComment = '';
          currentCommandLines = [];
        }
        return;
      }

      if (trimmed.startsWith('#')) {
        if (currentCommandLines.length > 0) {
          tiles.push(createTileObj(category, currentComment, currentCommandLines.join('\n')));
          currentComment = '';
          currentCommandLines = [];
        }
        currentComment = (currentComment ? currentComment + ' ' : '') + trimmed.replace(/^#\s*/, '').replace(/^[0-9.]+\s*/, '');
      } else {
        currentCommandLines.push(line);
      }
    });

    if (currentCommandLines.length > 0) {
      tiles.push(createTileObj(category, currentComment, currentCommandLines.join('\n')));
    }

    return tiles;
  }

  function createTileObj(category, comment, cmd) {
    var title = comment || cmd.split('\n')[0].substring(0, 48) + '...';
    return {
      category: category,
      title: title,
      command: cmd,
      badge: determineBadge(cmd, title),
      flags: extractFlags(cmd)
    };
  }

  function determineBadge(cmd, title) {
    var lower = (cmd + ' ' + title).toLowerCase();
    if (lower.indexOf('reboot') !== -1 || lower.indexOf('shutdown') !== -1 || lower.indexOf('kill -9') !== -1 || lower.indexOf('force') !== -1 || lower.indexOf('stop-computer') !== -1) {
      return { type: 'emergency', label: 'Emergency / Action' };
    }
    if (lower.indexOf('sudo') !== -1 || lower.indexOf('visudo') !== -1 || lower.indexOf('chage') !== -1 || lower.indexOf('usermod') !== -1 || lower.indexOf('runas') !== -1 || lower.indexOf('unlock-') !== -1 || lower.indexOf('disable-') !== -1) {
      return { type: 'elevated', label: 'Elevated / Sudo' };
    }
    if (lower.indexOf('get-') !== -1 || lower.indexOf('status') !== -1 || lower.indexOf('journalctl') !== -1 || lower.indexOf('grep') !== -1 || lower.indexOf('ss ') !== -1 || lower.indexOf('top') !== -1 || lower.indexOf('ps ') !== -1 || lower.indexOf('vmstat') !== -1 || lower.indexOf('iostat') !== -1) {
      return { type: 'diagnostic', label: 'Diagnostic' };
    }
    return { type: 'safe', label: 'Safe / Read' };
  }

  function extractFlags(cmd) {
    var flags = [];
    var common = [
      { f: '-u', d: 'Unit / Service filter' },
      { f: '-f', d: 'Follow tail live' },
      { f: '-b', d: 'Current boot only' },
      { f: '-p err', d: 'Error priority filter' },
      { f: '-Identity', d: 'Target identity' },
      { f: '-Filter', d: 'AD query expression' },
      { f: '-ComputerName', d: 'Remote host list' },
      { f: '-Force', d: 'Bypass confirmation' },
      { f: '--failed', d: 'Show only failed units' },
      { f: '-tulpn', d: 'TCP/UDP listening numeric' },
      { f: '-r', d: 'Reboot after shutdown' }
    ];

    common.forEach(function (item) {
      if (cmd.indexOf(item.f) !== -1) {
        flags.push({ flag: item.f, desc: item.d });
      }
    });

    return flags.slice(0, 3);
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
    document.addEventListener('DOMContentLoaded', initPoster);
  } else {
    initPoster();
  }

  // Handle client-side navigation in MkDocs Material
  if (typeof app !== 'undefined' && app.document$) {
    app.document$.subscribe(initPoster);
  }
})();
