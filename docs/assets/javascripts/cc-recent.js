/**
 * Command & Code — Recently viewed pages (WP-32)
 * Records the last 10 pages this visitor opened and lists them on the home page.
 * Client-side only: stored in this browser's localStorage, no cookies, never sent anywhere.
 * The home page opts in with <div id="cc-recent" hidden></div>; every other page is recorded.
 */

(function () {
  'use strict';

  var STORAGE_KEY = 'cc-recent-v1';
  var MAX_ITEMS = 10;
  var SITE_SUFFIX = ' - Command & Code';

  function load() {
    try {
      var items = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
      if (!Array.isArray(items)) { return []; }
      // Only same-site absolute paths with a title; anything else is dropped.
      return items.filter(function (item) {
        return item && typeof item.u === 'string' && typeof item.t === 'string' &&
          item.u.charAt(0) === '/' && item.u.charAt(1) !== '/';
      }).slice(0, MAX_ITEMS);
    } catch (e) {
      return [];
    }
  }

  function save(items) {
    try {
      if (items.length) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
      } else {
        localStorage.removeItem(STORAGE_KEY);
      }
    } catch (e) {
      // Storage blocked (private mode, site data disabled): the feature quietly does nothing.
    }
  }

  function pageTitle() {
    var heading = document.querySelector('.md-content article h1');
    var text = heading ? heading.textContent : document.title.replace(SITE_SUFFIX, '');
    return text.replace(/\s+/g, ' ').replace(/¶$/, '').trim();
  }

  function record() {
    var path = window.location.pathname;
    var title = pageTitle();
    // Skip the 404 page and anything without a title.
    if (!title || document.querySelector('.md-content article h1#__404') || /\/404(\.html)?$/.test(path)) {
      return;
    }
    var items = load().filter(function (item) { return item.u !== path; });
    items.unshift({ u: path, t: title });
    save(items.slice(0, MAX_ITEMS));
  }

  function render(box) {
    var items = load();
    box.textContent = '';
    if (!items.length) {
      box.hidden = true;
      return;
    }

    var header = document.createElement('p');
    header.className = 'cc-recent-head';
    var label = document.createElement('strong');
    label.textContent = 'Recently viewed';
    var clear = document.createElement('button');
    clear.type = 'button';
    clear.className = 'cc-recent-clear';
    clear.textContent = 'clear';
    clear.title = 'Forget the pages listed here (stored only in this browser)';
    clear.addEventListener('click', function () {
      save([]);
      render(box);
    });
    header.appendChild(label);
    header.appendChild(clear);

    var list = document.createElement('div');
    list.className = 'cc-searches cc-recent-list';
    items.forEach(function (item) {
      var link = document.createElement('a');
      link.href = item.u;
      link.textContent = item.t;
      list.appendChild(link);
    });

    box.appendChild(header);
    box.appendChild(list);
    box.hidden = false;
  }

  function onPage() {
    var box = document.getElementById('cc-recent');
    if (box) {
      render(box);
    } else {
      record();
    }
  }

  // Material instant navigation emits on the first load and on every page change.
  if (typeof window.document$ !== 'undefined' && window.document$.subscribe) {
    window.document$.subscribe(onPage);
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onPage);
  } else {
    onPage();
  }
})();
