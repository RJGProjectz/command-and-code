// ==========================================================================
// Command & Code — Interactive Web Enhancements (Pillar 1: Command Builder)
// ==========================================================================
(function () {
  'use strict';

  var PARAM_REGEX = /<([A-Z][A-Z0-9_]{2,})>/g;
  var EXCLUDED_TOKENS = new Set([
    'HTML', 'HTTP', 'HTTPS', 'JSON', 'TRUE', 'FALSE', 'NULL', 'POST', 'HEAD',
    'TYPE', 'NAME', 'DATA', 'FILE', 'TEXT', 'INFO', 'WARN', 'ERROR', 'ROOT',
    'VOID', 'CHAR', 'MAIN', 'STDOUT', 'STDIN', 'STDERR'
  ]);

  var pageParams = {};

  function getSessionStorageKey() {
    return 'cc_params_' + (window.location.pathname || 'root');
  }

  function loadSavedParams() {
    try {
      var saved = sessionStorage.getItem(getSessionStorageKey());
      if (saved) {
        pageParams = JSON.parse(saved);
      }
    } catch (e) {
      pageParams = {};
    }
  }

  function saveParams() {
    try {
      sessionStorage.setItem(getSessionStorageKey(), JSON.stringify(pageParams));
    } catch (e) {}
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function extractParamsFromText(text) {
    var found = new Set();
    var match;
    var re = new RegExp(PARAM_REGEX);
    while ((match = re.exec(text)) !== null) {
      var token = match[1];
      if (!EXCLUDED_TOKENS.has(token)) {
        found.add(token);
      }
    }
    return Array.from(found);
  }

  function interpolateCode(rawText, params) {
    return rawText.replace(PARAM_REGEX, function (match, token) {
      if (params[token] && params[token].trim().length > 0) {
        return params[token].trim();
      }
      return match;
    });
  }

  function interpolateCodeHtml(rawText, params) {
    // Replace with highlighted span
    var escaped = escapeHtml(rawText);
    var re = /&lt;([A-Z][A-Z0-9_]{2,})&gt;/g;
    return escaped.replace(re, function (match, token) {
      if (params[token] && params[token].trim().length > 0) {
        var val = escapeHtml(params[token].trim());
        return '<span class="cc-token-replaced">' + val + '</span>';
      }
      return match;
    });
  }

  function updateBlock(blockData) {
    var codeEl = blockData.codeEl;
    var rawText = blockData.rawText;
    var hasActiveParam = false;

    blockData.paramKeys.forEach(function (k) {
      if (pageParams[k] && pageParams[k].trim().length > 0) {
        hasActiveParam = true;
      }
    });

    if (hasActiveParam) {
      codeEl.innerHTML = interpolateCodeHtml(rawText, pageParams);
    } else {
      codeEl.innerHTML = blockData.origHtml;
    }
  }

  function updateAllBlocks(registry) {
    registry.forEach(function (blockData) {
      updateBlock(blockData);
    });
  }

  function initCommandBuilders() {
    loadSavedParams();
    var codeBlocks = document.querySelectorAll('.md-typeset pre > code');
    if (!codeBlocks.length) return;

    var registry = [];

    codeBlocks.forEach(function (codeEl, index) {
      // Avoid double initialization
      if (codeEl.hasAttribute('data-cc-builder-initialized')) return;

      var rawText = codeEl.textContent;
      var params = extractParamsFromText(rawText);

      // Only mount builder if placeholders are present
      if (!params || params.length === 0) return;

      codeEl.setAttribute('data-cc-builder-initialized', 'true');
      var origHtml = codeEl.innerHTML;

      var highlightContainer = codeEl.closest('.highlight') || codeEl.closest('pre');
      if (!highlightContainer) return;

      var blockData = {
        id: 'cc-block-' + index,
        codeEl: codeEl,
        rawText: rawText,
        origHtml: origHtml,
        paramKeys: params,
        highlightContainer: highlightContainer
      };
      registry.push(blockData);

      // Build Parameter Bar
      var bar = document.createElement('div');
      bar.className = 'cc-param-bar';
      bar.id = 'cc-bar-' + index;

      var header = document.createElement('div');
      header.className = 'cc-param-header';

      var title = document.createElement('div');
      title.className = 'cc-param-title';
      title.innerHTML = '<svg viewBox="0 0 24 24"><path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3zm1 14h-2v-2h2v2zm0-4h-2V7h2v5z"/></svg> Parameterized Builder';

      var actions = document.createElement('div');
      actions.className = 'cc-param-actions';

      var copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.className = 'cc-param-btn cc-param-btn--copy';
      copyBtn.innerHTML = '⚡ Copy Prepared';
      copyBtn.addEventListener('click', function () {
        var interpolated = interpolateCode(rawText, pageParams);
        navigator.clipboard.writeText(interpolated).then(function () {
          var origText = copyBtn.innerHTML;
          copyBtn.innerHTML = '✓ Copied!';
          copyBtn.classList.add('cc-param-btn--copied');
          setTimeout(function () {
            copyBtn.innerHTML = origText;
            copyBtn.classList.remove('cc-param-btn--copied');
          }, 1800);
        });
      });

      var resetBtn = document.createElement('button');
      resetBtn.type = 'button';
      resetBtn.className = 'cc-param-btn';
      resetBtn.innerText = 'Reset';
      resetBtn.addEventListener('click', function () {
        params.forEach(function (k) {
          delete pageParams[k];
        });
        saveParams();
        // Update all input fields in DOM
        document.querySelectorAll('.cc-param-input').forEach(function (inp) {
          var k = inp.getAttribute('data-param-key');
          if (params.indexOf(k) !== -1) {
            inp.value = '';
          }
        });
        updateAllBlocks(registry);
      });

      actions.appendChild(resetBtn);
      actions.appendChild(copyBtn);
      header.appendChild(title);
      header.appendChild(actions);
      bar.appendChild(header);

      // Grid of parameter input fields
      var grid = document.createElement('div');
      grid.className = 'cc-param-grid';

      params.forEach(function (paramKey) {
        var field = document.createElement('div');
        field.className = 'cc-param-field';

        var label = document.createElement('label');
        label.className = 'cc-param-label';
        label.innerText = paramKey + ':';

        var input = document.createElement('input');
        input.type = 'text';
        input.className = 'cc-param-input';
        input.setAttribute('data-param-key', paramKey);
        input.placeholder = '<' + paramKey + '>';
        if (pageParams[paramKey]) {
          input.value = pageParams[paramKey];
        }

        input.addEventListener('input', function (e) {
          var val = e.target.value;
          if (val && val.trim().length > 0) {
            pageParams[paramKey] = val;
          } else {
            delete pageParams[paramKey];
          }
          saveParams();

          // Sync all inputs on the page with the same parameter key
          document.querySelectorAll('.cc-param-input[data-param-key="' + paramKey + '"]').forEach(function (otherInput) {
            if (otherInput !== input) {
              otherInput.value = val;
            }
          });

          updateAllBlocks(registry);
        });

        field.appendChild(label);
        field.appendChild(input);
        grid.appendChild(field);
      });

      bar.appendChild(grid);

      // Insert bar immediately before the highlight container
      highlightContainer.parentNode.insertBefore(bar, highlightContainer);

      // Intercept native clipboard button if present on highlight container
      var nativeClipboardBtn = highlightContainer.querySelector('button.md-clipboard');
      if (nativeClipboardBtn) {
        nativeClipboardBtn.addEventListener('click', function (e) {
          var interpolated = interpolateCode(rawText, pageParams);
          // Set clipboard data
          navigator.clipboard.writeText(interpolated);
        }, true);
      }
    });

    // Initial render of blocks with any saved session parameters
    updateAllBlocks(registry);
  }

  // Lifecycle mounting
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initCommandBuilders);
  } else {
    initCommandBuilders();
  }

  // Handle Material for MkDocs instant navigation (pjax)
  if (typeof app !== 'undefined' && app.document$) {
    app.document$.subscribe(function () {
      initCommandBuilders();
    });
  } else if (typeof window !== 'undefined' && 'MutationObserver' in window) {
    var observer = new MutationObserver(function () {
      if (document.querySelector('.md-typeset pre > code:not([data-cc-builder-initialized])')) {
        initCommandBuilders();
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }
})();
