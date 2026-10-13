/**
 * Command & Code — Search facets (WP-18)
 * Adds Platform, Language and Type chips to the search dialog and hides results that do not
 * match. Values come from each page's front matter via assets/facets.json (hooks/cc_meta.py).
 * Several chips in one group widen the filter (OR); chips in different groups narrow it (AND).
 * While a filter is on, an own list replaces Material's: its loaded matches, then every other page
 * that contains every query term in its title, tags, aliases or text (page text comes from
 * search/search_index.json, loaded on first use). An empty query lists every page in the filter.
 * Client-side only: no storage, nothing sent anywhere.
 */

(function () {
  'use strict';

  var GROUPS = [
    { key: 'p', label: 'Platform' },
    { key: 'l', label: 'Language' },
    { key: 't', label: 'Type' }
  ];
  var TYPE_LABELS = {
    entry: 'Entry', workflow: 'Workflow', concept: 'Concept', reference: 'Reference',
    tool: 'Tool', index: 'Section index'
  };

  var facets = null;       // page path (relative to the site root) -> {t, p, l}
  var siteRoot = null;     // absolute pathname of the site root, ending in '/'
  var selected = { p: {}, l: {}, t: {} };
  var bar = null;
  var own = null;    // own result list, shown instead of Material's while a filter is on
  var texts = null;  // page path -> lower-case page text from search_index.json (loaded on first filter)
  var loading = false;

  function config() {
    try {
      return JSON.parse(document.getElementById('__config').textContent);
    } catch (e) {
      return { base: '.' };
    }
  }

  function pageKey(href) {
    var path = new URL(href, location.href).pathname;
    if (path.indexOf(siteRoot) !== 0) { return null; }
    return decodeURI(path.slice(siteRoot.length)) || './'; // MkDocs gives the home page the URL './'
  }

  function isActive() {
    return GROUPS.some(function (g) { return Object.keys(selected[g.key]).length > 0; });
  }

  function matches(entry) {
    if (!entry) { return !isActive(); }
    return GROUPS.every(function (g) {
      var wanted = Object.keys(selected[g.key]);
      if (!wanted.length) { return true; }
      var values = g.key === 't' ? [entry.t] : entry[g.key];
      return values.some(function (v) { return selected[g.key][v]; });
    });
  }

  function terms() {
    var input = document.querySelector('.md-search__input');
    var q = input ? input.value.toLowerCase() : '';
    return q.split(/[^0-9a-z#+._-]+/).filter(function (w) { return w.length > 1; });
  }

  // Page text from Material's own index, grouped by page. The search worker has already fetched
  // this file, so the request is normally answered from the browser cache.
  function loadTexts() {
    if (texts || loading) { return; }
    loading = true;
    fetch(new URL('search/search_index.json', new URL(siteRoot, location.href)).href)
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        var byPage = {};
        ((data && data.docs) || []).forEach(function (doc) {
          var key = doc.location.split('#')[0] || './';
          byPage[key] = (byPage[key] || '') + ' ' + doc.title + ' ' + doc.text.replace(/<[^>]+>/g, ' ');
        });
        Object.keys(byPage).forEach(function (k) { byPage[k] = byPage[k].toLowerCase(); });
        texts = byPage;
        apply();
      })
      .catch(function () { texts = {}; });
  }

  // Facet-matching pages that contain every query term, best first: title hits, then tags and
  // aliases, then body text.
  // Material renders its results in batches (10, then 4 per scroll); with a filter on, most of a
  // batch is hidden and the next one never loads. This list does not depend on that paging.
  function ownMatches(words, skip) {
    var found = [];
    Object.keys(facets).forEach(function (path) {
      var entry = facets[path];
      if (skip[path] || !matches(entry)) { return; }
      var title = (entry.n || path).toLowerCase();
      var keys = (entry.k || []).join(' ').toLowerCase();
      var body = (texts && texts[path]) || '';
      var score = 0;
      for (var i = 0; i < words.length; i += 1) {
        if (title.indexOf(words[i]) !== -1) {
          score += 100;
        } else if (keys.indexOf(words[i]) !== -1) {
          score += 50;
        } else if (body.indexOf(words[i]) !== -1) {
          score += Math.min(body.split(words[i]).length - 1, 20);
        } else {
          return;
        }
      }
      found.push({ path: path, entry: entry, score: score });
    });
    return found.sort(function (a, b) {
      return b.score - a.score ||
        (a.entry.t === 'index') - (b.entry.t === 'index') ||
        (a.entry.n || a.path).localeCompare(b.entry.n || b.path);
    });
  }

  function ownItem(path, entry) {
    var li = document.createElement('li');
    li.className = 'md-search-result__item';
    var a = document.createElement('a');
    a.className = 'md-search-result__link';
    a.href = new URL(path === './' ? '' : path, new URL(siteRoot, location.href)).href;
    var article = document.createElement('article');
    article.className = 'md-search-result__article md-typeset';
    var h = document.createElement('h1');
    h.textContent = entry.n || path;
    var meta = document.createElement('p');
    meta.className = 'cc-facets__meta';
    meta.textContent = [TYPE_LABELS[entry.t] || entry.t].concat(entry.p, entry.l).join(' · ');
    article.appendChild(h);
    article.appendChild(meta);
    a.appendChild(article);
    li.appendChild(a);
    return li;
  }

  function apply() {
    var list = document.querySelector('.md-search-result__list:not(.cc-facets__list)');
    if (!list || !bar || !own) { return; }
    var items = list.querySelectorAll('.md-search-result__item');
    var active = isActive();
    var words = terms();
    var status = bar.querySelector('.cc-facets__status');
    bar.querySelector('.cc-facets__clear').hidden = !active;
    bar.hidden = items.length === 0 && !active && !words.length;
    list.hidden = active;
    own.hidden = !active;
    own.textContent = '';
    if (!active) {
      status.textContent = '';
      return;
    }
    if (words.length) { loadTexts(); }
    // Material's loaded results first (body-text matches, highlighted snippets), then the rest.
    var seen = {};
    var shown = 0;
    Array.prototype.forEach.call(items, function (item) {
      var link = item.querySelector('a.md-search-result__link');
      var key = link ? pageKey(link.href) : null;
      if (!link || seen[key] || !matches(facets[key])) { return; }
      seen[key] = true;
      own.appendChild(item.cloneNode(true));
      shown += 1;
    });
    ownMatches(words, seen).forEach(function (m) {
      own.appendChild(ownItem(m.path, m.entry));
      shown += 1;
    });
    status.textContent = shown + (shown === 1 ? ' page matches' : ' pages match') +
      (words.length ? '' : ' the filter');
  }

  function counts(key) {
    var tally = {};
    Object.keys(facets).forEach(function (path) {
      var entry = facets[path];
      (key === 't' ? [entry.t] : entry[key]).forEach(function (v) { tally[v] = (tally[v] || 0) + 1; });
    });
    return Object.keys(tally).sort(function (a, b) { return tally[b] - tally[a] || a.localeCompare(b); });
  }

  function chip(groupKey, value) {
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'cc-facets__chip';
    button.textContent = groupKey === 't' ? (TYPE_LABELS[value] || value) : value;
    button.setAttribute('aria-pressed', selected[groupKey][value] ? 'true' : 'false');
    button.addEventListener('click', function () {
      if (selected[groupKey][value]) {
        delete selected[groupKey][value];
      } else {
        selected[groupKey][value] = true;
      }
      button.setAttribute('aria-pressed', selected[groupKey][value] ? 'true' : 'false');
      apply();
    });
    return button;
  }

  function buildBar() {
    var el = document.createElement('div');
    el.className = 'cc-facets';
    el.setAttribute('role', 'group');
    el.setAttribute('aria-label', 'Filter search results');
    GROUPS.forEach(function (g) {
      var row = document.createElement('div');
      row.className = 'cc-facets__row';
      var label = document.createElement('span');
      label.className = 'cc-facets__label';
      label.textContent = g.label;
      row.appendChild(label);
      counts(g.key).forEach(function (value) { row.appendChild(chip(g.key, value)); });
      el.appendChild(row);
    });
    var foot = document.createElement('div');
    foot.className = 'cc-facets__foot';
    var status = document.createElement('span');
    status.className = 'cc-facets__status';
    status.setAttribute('aria-live', 'polite');
    var clear = document.createElement('button');
    clear.type = 'button';
    clear.className = 'cc-facets__clear';
    clear.textContent = 'Clear filters';
    clear.hidden = true;
    clear.addEventListener('click', function () {
      selected = { p: {}, l: {}, t: {} };
      Array.prototype.forEach.call(el.querySelectorAll('.cc-facets__chip'), function (b) {
        b.setAttribute('aria-pressed', 'false');
      });
      apply();
    });
    foot.appendChild(status);
    foot.appendChild(clear);
    el.appendChild(foot);
    el.hidden = true;
    return el;
  }

  function attach() {
    var result = document.querySelector('.md-search-result');
    var list = document.querySelector('.md-search-result__list');
    if (!facets || !result || !list || result.querySelector('.cc-facets')) { return; }
    bar = buildBar();
    result.insertBefore(bar, list);
    own = document.createElement('ol');
    own.className = 'md-search-result__list cc-facets__list';
    own.hidden = true;
    own.addEventListener('click', function (event) {
      // Close the search dialog, as Material does for its own results.
      if (!event.target.closest('a')) { return; }
      var toggle = document.getElementById('__search');
      if (toggle && toggle.checked) { toggle.checked = false; toggle.dispatchEvent(new Event('change')); }
    });
    list.parentNode.insertBefore(own, list.nextSibling);
    new MutationObserver(apply).observe(list, { childList: true });
    var input = document.querySelector('.md-search__input');
    if (input) { input.addEventListener('input', apply); }
    apply();
  }

  function init() {
    var cfg = config();
    siteRoot = new URL((cfg.base || '.') + '/', location.href).pathname;
    fetch(new URL('assets/facets.json', new URL(siteRoot, location.href)).href)
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data) { return; }
        facets = data;
        attach();
        // With instant navigation the header can be swapped; re-attach when that happens.
        if (window.document$ && typeof window.document$.subscribe === 'function') {
          window.document$.subscribe(attach);
        }
      })
      .catch(function () { /* no facet index: search works as before */ });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
