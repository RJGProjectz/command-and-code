/**
 * Command & Code — Knowledge graph (WP-20)
 * Reads assets/graph.json (written by hooks/cc_meta.py at build time) and draws:
 *   - a small "local graph" (this page and the pages it links to or is linked from) at the
 *     top of the right sidebar on every page; hidden below 76.25em like the sidebar itself;
 *   - the full graph on the Graph page (#cc-graph), with filters by section and a search.
 * Hand-written canvas force layout: no third-party library, nothing loaded from a CDN.
 * Titles are drawn on the canvas, never inserted as HTML.
 */

(function () {
  'use strict';

  var script = document.currentScript;
  var ROOT = script ? script.src.replace(/assets\/javascripts\/cc-graph\.js(\?.*)?$/, '') : '/';

  // Section (top-level docs folder) -> label and colour; order is the order of the filters.
  var SECTIONS = [
    ['platforms', 'Platforms', '#4fc3f7'],
    ['languages', 'Shells', '#81c784'],
    ['tasks', 'Tasks', '#ffb74d'],
    ['detection', 'Detection', '#ef5350'],
    ['fundamentals', 'Concepts', '#ce93d8'],
    ['apis', 'APIs', '#4db6ac'],
    ['toolbox', 'Toolbox', '#f48fb1'],
    ['references', 'Reference', '#bcaaa4'],
    ['home', 'Home', '#eeeeee']
  ];
  var COLOR = {};
  SECTIONS.forEach(function (s) { COLOR[s[0]] = s[2]; });

  var graphPromise = null;

  function normalizePath(path) {
    return decodeURI(path).replace(/index\.html$/, '');
  }

  function loadGraph() {
    if (!graphPromise) {
      graphPromise = fetch(ROOT + 'assets/graph.json')
        .then(function (response) {
          if (!response.ok) { throw new Error('graph.json: HTTP ' + response.status); }
          return response.json();
        })
        .then(function (data) {
          var byPath = {};
          data.nodes.forEach(function (node, i) {
            node.index = i;
            node.neighbors = [];
            byPath[normalizePath(new URL(node.url, ROOT).pathname)] = node;
          });
          data.links.forEach(function (pair) {
            data.nodes[pair[0]].neighbors.push(pair[1]);
            data.nodes[pair[1]].neighbors.push(pair[0]);
          });
          data.byPath = byPath;
          return data;
        });
      graphPromise.catch(function () { graphPromise = null; });
    }
    return graphPromise;
  }

  // Follow a link through Material's instant navigation when it is active.
  function navigate(node) {
    var a = document.createElement('a');
    a.href = new URL(node.url, ROOT).href;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function cssVar(name, fallback) {
    var value = getComputedStyle(document.body).getPropertyValue(name).trim();
    return value || fallback;
  }

  // ------------------------------------------------------------------ graph view

  /**
   * GraphView: force simulation + canvas renderer + pointer interaction.
   * opts: { zoom: bool, repulsion, linkLength, current: node index, autoFit: bool }
   */
  function GraphView(canvas, data, nodeIndexes, opts) {
    var self = this;
    self.canvas = canvas;
    self.ctx = canvas.getContext('2d');
    self.opts = opts;
    self.data = data;
    self.k = 1; self.tx = 0; self.ty = 0;
    self.hover = null;
    self.query = '';
    self.userMoved = false;
    self.alpha = 1;
    self.running = false;

    var local = {};
    self.nodes = nodeIndexes.map(function (index, i) {
      // Phyllotaxis start: deterministic and already roughly round.
      var radius = 8 * Math.sqrt(0.5 + i), angle = i * Math.PI * (3 - Math.sqrt(5));
      var state = { d: data.nodes[index], x: radius * Math.cos(angle), y: radius * Math.sin(angle), vx: 0, vy: 0, deg: 0, hidden: false };
      local[index] = state;
      return state;
    });
    self.links = [];
    data.links.forEach(function (pair) {
      var s = local[pair[0]], t = local[pair[1]];
      if (s && t) { self.links.push({ s: s, t: t }); s.deg += 1; t.deg += 1; }
    });
    self.nodes.forEach(function (n) { n.r = 2.5 + Math.sqrt(n.deg) * (opts.zoom ? 0.9 : 0.6); n.ax = 0; n.ay = 0; });
    if (opts.cluster) {
      // Each section gets its own spot on a circle, so sections read as coloured clusters
      // instead of one ball held together by the index pages.
      var present = SECTIONS.filter(function (s) {
        return self.nodes.some(function (n) { return n.d.section === s[0]; });
      });
      self.nodes.forEach(function (n) {
        var i = present.findIndex(function (s) { return s[0] === n.d.section; });
        var angle = 2 * Math.PI * i / present.length;
        n.ax = opts.cluster * Math.cos(angle); n.ay = opts.cluster * Math.sin(angle);
      });
    }
    self.colors = {
      edge: cssVar('--md-default-fg-color--lightest', 'rgba(255,255,255,0.12)'),
      text: cssVar('--md-default-fg-color', '#e0e0e0'),
      bg: cssVar('--md-default-bg-color', '#1e2129'),
      accent: cssVar('--md-accent-fg-color', '#ffab40'),
      font: getComputedStyle(document.body).fontFamily || 'sans-serif'
    };
    self.bindPointer();
    self.resize();
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      for (var i = 0; i < 300 && self.alpha > 0.005; i += 1) { self.tick(); }
      self.fit();
      self.draw();
    } else {
      self.start(1);
    }
  }

  GraphView.prototype.visible = function () {
    return this.nodes.filter(function (n) { return !n.hidden; });
  };

  GraphView.prototype.tick = function () {
    var nodes = this.visible(), n = nodes.length, a = this.alpha, opts = this.opts;
    var rep = opts.repulsion, reach2 = (opts.reach || 600) * (opts.reach || 600), i, j, p, q, dx, dy, d2, f;
    for (i = 0; i < n; i += 1) {
      p = nodes[i];
      for (j = i + 1; j < n; j += 1) {
        q = nodes[j];
        dx = q.x - p.x; dy = q.y - p.y;
        d2 = dx * dx + dy * dy || 0.01;
        if (d2 > reach2) { continue; }
        f = rep * a / d2;
        p.vx -= dx * f; p.vy -= dy * f;
        q.vx += dx * f; q.vy += dy * f;
      }
    }
    this.links.forEach(function (link) {
      var s = link.s, t = link.t;
      if (s.hidden || t.hidden) { return; }
      var lx = t.x - s.x, ly = t.y - s.y, d = Math.sqrt(lx * lx + ly * ly) || 0.01;
      // Weaker springs on hubs, and the low-degree end does most of the moving: a section
      // index pulled by 300 springs at full strength overshoots and the layout blows up.
      var g = (d - opts.linkLength) / d * a * 0.5 / Math.min(s.deg, t.deg);
      if (opts.cluster && s.d.section !== t.d.section) { g *= 0.15; }
      var bias = s.deg / (s.deg + t.deg);
      s.vx += lx * g * (1 - bias); s.vy += ly * g * (1 - bias);
      t.vx -= lx * g * bias; t.vy -= ly * g * bias;
    });
    nodes.forEach(function (node) {
      var pull = opts.cluster ? 0.08 : 0.004;
      node.vx -= (node.x - node.ax) * pull * a;
      node.vy -= (node.y - node.ay) * pull * a;
      if (node === this.dragged) { node.vx = 0; node.vy = 0; return; }
      node.vx *= 0.6; node.vy *= 0.6;
      node.x += node.vx; node.y += node.vy;
    }, this);
    this.alpha *= 0.985;
  };

  GraphView.prototype.start = function (alpha) {
    var self = this;
    self.alpha = Math.max(self.alpha, alpha);
    if (self.running) { return; }
    self.running = true;
    function frame() {
      if (!self.canvas.isConnected) { self.running = false; self.destroy(); return; }
      self.tick();
      if (!self.userMoved && self.opts.autoFit !== false) { self.fit(); }
      self.draw();
      if (self.alpha > 0.005 || self.dragged) {
        window.requestAnimationFrame(frame);
      } else {
        self.running = false;
      }
    }
    window.requestAnimationFrame(frame);
  };

  GraphView.prototype.resize = function () {
    var rect = this.canvas.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
    this.width = rect.width; this.height = rect.height;
    this.canvas.width = Math.max(1, Math.round(rect.width * dpr));
    this.canvas.height = Math.max(1, Math.round(rect.height * dpr));
    this.dpr = dpr;
    if (!this.userMoved) { this.fit(); }
    this.draw();
  };

  GraphView.prototype.fit = function () {
    var nodes = this.visible();
    if (!nodes.length || !this.width) { return; }
    var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach(function (n) {
      minX = Math.min(minX, n.x - n.r); maxX = Math.max(maxX, n.x + n.r);
      minY = Math.min(minY, n.y - n.r); maxY = Math.max(maxY, n.y + n.r);
    });
    var pad = 16, w = Math.max(maxX - minX, 40), h = Math.max(maxY - minY, 40);
    this.k = Math.min((this.width - pad * 2) / w, (this.height - pad * 2) / h, this.opts.zoom ? 4 : 2.5);
    this.tx = -(minX + maxX) / 2 * this.k;
    this.ty = -(minY + maxY) / 2 * this.k;
  };

  GraphView.prototype.toWorld = function (sx, sy) {
    return { x: (sx - this.width / 2 - this.tx) / this.k, y: (sy - this.height / 2 - this.ty) / this.k };
  };

  GraphView.prototype.nodeAt = function (sx, sy) {
    var w = this.toWorld(sx, sy), best = null, bestD = Infinity, slop = 4 / this.k;
    this.visible().forEach(function (n) {
      var dx = n.x - w.x, dy = n.y - w.y, d = Math.sqrt(dx * dx + dy * dy);
      if (d < n.r + slop && d < bestD) { best = n; bestD = d; }
    });
    return best;
  };

  GraphView.prototype.matches = function (node) {
    return this.query !== '' && node.d.title.toLowerCase().indexOf(this.query) !== -1;
  };

  GraphView.prototype.draw = function () {
    var ctx = this.ctx, k = this.k, self = this, colors = this.colors;
    var focus = this.hover;
    var related = {};
    if (focus) {
      related[focus.d.index] = true;
      focus.d.neighbors.forEach(function (i) { related[i] = true; });
    }
    var searching = this.query !== '';

    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.clearRect(0, 0, this.width, this.height);
    ctx.translate(this.width / 2 + this.tx, this.height / 2 + this.ty);
    ctx.scale(k, k);

    ctx.lineWidth = 1 / k;
    this.links.forEach(function (link) {
      if (link.s.hidden || link.t.hidden) { return; }
      var lit = focus && (link.s === focus || link.t === focus);
      ctx.globalAlpha = (focus ? (lit ? 0.9 : 0.15) : (searching ? 0.25 : 1)) * (lit ? 1 : self.opts.edgeAlpha || 1);
      ctx.strokeStyle = lit ? colors.accent : colors.edge;
      ctx.beginPath();
      ctx.moveTo(link.s.x, link.s.y);
      ctx.lineTo(link.t.x, link.t.y);
      ctx.stroke();
    });

    var labelled = [];
    this.visible().forEach(function (n) {
      var isCurrent = n.d.index === self.opts.current;
      var hit = self.matches(n);
      var dim = (focus && !related[n.d.index]) || (searching && !hit);
      ctx.globalAlpha = dim ? 0.2 : 1;
      ctx.fillStyle = COLOR[n.d.section] || colors.text;
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();
      if (isCurrent || hit) {
        ctx.lineWidth = 2 / k;
        ctx.strokeStyle = colors.accent;
        ctx.stroke();
      }
      var show = n === focus || isCurrent || hit ||
        (focus && related[n.d.index] && self.opts.zoom) ||
        (!focus && !searching && (self.opts.labels === 'all' || k * n.r > 9));
      if (show) { labelled.push(n); }
    });

    ctx.globalAlpha = 1;
    ctx.font = (11 / k) + 'px ' + colors.font;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.lineJoin = 'round';
    labelled.forEach(function (n) {
      var text = n.d.title.length > 48 ? n.d.title.slice(0, 46) + '…' : n.d.title;
      var y = n.y + n.r + 2 / k;
      ctx.lineWidth = 3 / k;
      ctx.strokeStyle = colors.bg;
      ctx.strokeText(text, n.x, y);
      ctx.fillStyle = colors.text;
      ctx.fillText(text, n.x, y);
    });
  };

  GraphView.prototype.zoomAt = function (sx, sy, factor) {
    var k = Math.min(Math.max(this.k * factor, 0.05), 8);
    var cx = sx - this.width / 2, cy = sy - this.height / 2;
    this.tx = cx - (cx - this.tx) * (k / this.k);
    this.ty = cy - (cy - this.ty) * (k / this.k);
    this.k = k;
    this.userMoved = true;
    this.draw();
  };

  GraphView.prototype.bindPointer = function () {
    var self = this, canvas = this.canvas, pointers = {}, press = null, pinch = null;

    function point(event) {
      var rect = canvas.getBoundingClientRect();
      return { x: event.clientX - rect.left, y: event.clientY - rect.top };
    }
    function pinchState() {
      var ids = Object.keys(pointers);
      var a = pointers[ids[0]], b = pointers[ids[1]];
      return { d: Math.hypot(a.x - b.x, a.y - b.y) || 1, x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    }

    self.handlers = {
      pointerdown: function (event) {
        var p = point(event);
        pointers[event.pointerId] = p;
        canvas.setPointerCapture(event.pointerId);
        if (Object.keys(pointers).length === 2 && self.opts.zoom) {
          pinch = pinchState(); press = null; self.dragged = null;
          return;
        }
        var node = self.nodeAt(p.x, p.y);
        press = { x: p.x, y: p.y, node: node, tx: self.tx, ty: self.ty, moved: false };
        if (node) { self.dragged = node; self.start(0.3); }
      },
      pointermove: function (event) {
        var p = point(event);
        if (pointers[event.pointerId]) { pointers[event.pointerId] = p; }
        if (pinch && Object.keys(pointers).length === 2) {
          var now = pinchState();
          self.zoomAt(now.x, now.y, now.d / pinch.d);
          pinch = now;
          return;
        }
        if (press) {
          if (Math.abs(p.x - press.x) + Math.abs(p.y - press.y) > 4) { press.moved = true; }
          if (press.node) {
            var w = self.toWorld(p.x, p.y);
            press.node.x = w.x; press.node.y = w.y;
            self.start(0.3);
          } else if (self.opts.zoom && press.moved) {
            self.tx = press.tx + p.x - press.x;
            self.ty = press.ty + p.y - press.y;
            self.userMoved = true;
            self.draw();
          }
          return;
        }
        var hover = self.nodeAt(p.x, p.y);
        if (hover !== self.hover) {
          self.hover = hover;
          canvas.style.cursor = hover ? 'pointer' : '';
          canvas.title = hover ? hover.d.title : '';
          self.draw();
        }
      },
      pointerup: function (event) {
        delete pointers[event.pointerId];
        if (pinch) { if (Object.keys(pointers).length < 2) { pinch = null; } return; }
        var done = press;
        press = null;
        self.dragged = null;
        if (done && done.node && !done.moved) { navigate(done.node.d); }
      },
      pointerleave: function () {
        if (!press && self.hover) { self.hover = null; canvas.style.cursor = ''; self.draw(); }
      },
      wheel: function (event) {
        if (!self.opts.zoom) { return; }
        event.preventDefault();
        var p = point(event);
        self.zoomAt(p.x, p.y, Math.exp(-event.deltaY * 0.0015));
      }
    };
    self.handlers.pointercancel = self.handlers.pointerup;
    Object.keys(self.handlers).forEach(function (name) {
      canvas.addEventListener(name, self.handlers[name], name === 'wheel' ? { passive: false } : false);
    });
    if (window.ResizeObserver) {
      self.observer = new ResizeObserver(function () { self.resize(); });
      self.observer.observe(canvas);
    }
  };

  GraphView.prototype.destroy = function () {
    if (this.observer) { this.observer.disconnect(); this.observer = null; }
  };

  // ------------------------------------------------------------------ local graph

  function currentNode(data) {
    return data.byPath[normalizePath(window.location.pathname)] || null;
  }

  function mountLocal(data) {
    var sidebar = document.querySelector('.md-sidebar--secondary .md-sidebar__inner');
    if (!sidebar || document.getElementById('cc-graph') || sidebar.querySelector('.cc-localgraph')) { return; }
    var node = currentNode(data);
    if (!node) { return; }
    var box = document.createElement('div');
    box.className = 'cc-localgraph';
    var head = document.createElement('div');
    head.className = 'cc-localgraph__head';
    var title = document.createElement('span');
    title.textContent = 'Graph';
    var open = document.createElement('a');
    open.href = ROOT + 'graph/';
    open.textContent = 'Full graph';
    head.appendChild(title);
    head.appendChild(open);
    var canvas = document.createElement('canvas');
    canvas.className = 'cc-localgraph__canvas';
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', 'Pages linked with ' + node.title + ': ' + node.neighbors.length);
    box.appendChild(head);
    box.appendChild(canvas);
    sidebar.insertBefore(box, sidebar.firstChild);

    var seen = {}, indexes = [node.index];
    seen[node.index] = true;
    node.neighbors.forEach(function (i) { if (!seen[i]) { seen[i] = true; indexes.push(i); } });
    new GraphView(canvas, data, indexes, { zoom: false, repulsion: 40, linkLength: 40, current: node.index });
  }

  // ------------------------------------------------------------------ full graph page

  function mountFull(data, host) {
    if (host.getAttribute('data-ready')) { return; }
    host.setAttribute('data-ready', '1');
    host.textContent = '';

    var bar = document.createElement('div');
    bar.className = 'cc-graph__bar';
    var search = document.createElement('input');
    search.type = 'search';
    search.placeholder = 'Highlight pages…';
    search.className = 'cc-graph__search';
    search.setAttribute('aria-label', 'Highlight pages whose title contains');
    bar.appendChild(search);

    var counts = {};
    data.nodes.forEach(function (n) { counts[n.section] = (counts[n.section] || 0) + 1; });
    var filters = document.createElement('div');
    filters.className = 'cc-graph__filters';
    var boxes = {};
    SECTIONS.forEach(function (s) {
      if (!counts[s[0]]) { return; }
      var label = document.createElement('label');
      label.className = 'cc-graph__filter';
      var input = document.createElement('input');
      input.type = 'checkbox';
      input.checked = true;
      boxes[s[0]] = input;
      var dot = document.createElement('span');
      dot.className = 'cc-graph__dot';
      dot.style.background = s[2];
      label.appendChild(input);
      label.appendChild(dot);
      label.appendChild(document.createTextNode(s[1] + ' (' + counts[s[0]] + ')'));
      filters.appendChild(label);
    });
    var hubLabel = document.createElement('label');
    hubLabel.className = 'cc-graph__filter';
    var hubs = document.createElement('input');
    hubs.type = 'checkbox';
    hubs.checked = true;
    hubLabel.appendChild(hubs);
    hubLabel.appendChild(document.createTextNode('Index pages'));
    filters.appendChild(hubLabel);
    bar.appendChild(filters);

    var tools = document.createElement('div');
    tools.className = 'cc-graph__tools';
    function button(text, label, action) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'md-button cc-graph__btn';
      b.textContent = text;
      b.setAttribute('aria-label', label);
      b.addEventListener('click', action);
      tools.appendChild(b);
    }
    bar.appendChild(tools);

    var canvas = document.createElement('canvas');
    canvas.className = 'cc-graph__canvas';
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', 'Graph of ' + data.nodes.length + ' pages and ' + data.links.length + ' links');
    var status = document.createElement('p');
    status.className = 'cc-graph__status';
    host.appendChild(bar);
    host.appendChild(canvas);
    host.appendChild(status);

    var all = data.nodes.map(function (n) { return n.index; });
    var view = new GraphView(canvas, data, all, { zoom: true, repulsion: 60, reach: 90, linkLength: 40, cluster: 320, edgeAlpha: 0.45 });

    button('+', 'Zoom in', function () { view.zoomAt(view.width / 2, view.height / 2, 1.4); });
    button('−', 'Zoom out', function () { view.zoomAt(view.width / 2, view.height / 2, 1 / 1.4); });
    button('Fit', 'Fit the graph to the view', function () { view.userMoved = false; view.fit(); view.draw(); });

    // Filters change the layout (reheat); the search only re-colours it.
    function update(relayout) {
      var shown = 0;
      view.nodes.forEach(function (n) {
        var box = boxes[n.d.section];
        n.hidden = (box && !box.checked) || (!hubs.checked && n.d.type === 'index');
        if (!n.hidden) { shown += 1; }
      });
      var hits = view.query ? view.visible().filter(function (n) { return view.matches(n); }).length : null;
      status.textContent = shown + ' of ' + view.nodes.length + ' pages shown' +
        (hits === null ? '' : ' · ' + hits + ' match "' + search.value.trim() + '"') +
        ' · click a page to open it, drag to move, scroll or pinch to zoom';
      if (relayout) {
        view.userMoved = false;
        view.start(0.5);
      } else {
        view.draw();
      }
    }
    function relayout() { update(true); }
    Object.keys(boxes).forEach(function (key) { boxes[key].addEventListener('change', relayout); });
    hubs.addEventListener('change', relayout);
    search.addEventListener('input', function () {
      view.query = search.value.trim().toLowerCase();
      update(false);
    });
    update(false);
  }

  // ------------------------------------------------------------------ boot

  function onPage() {
    var host = document.getElementById('cc-graph');
    var wantsLocal = window.matchMedia('(min-width: 76.25em)').matches &&
      document.querySelector('.md-sidebar--secondary .md-sidebar__inner');
    if (!host && !wantsLocal) { return; }
    loadGraph().then(function (data) {
      if (host) { mountFull(data, host); } else { mountLocal(data); }
    }).catch(function (error) {
      if (host) { host.textContent = 'The graph could not be loaded (' + error.message + ').'; }
    });
  }

  // Material instant navigation emits on the first load and on every page change.
  if (typeof window.document$ !== 'undefined' && window.document$.subscribe) {
    window.document$.subscribe(onPage);
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onPage);
  } else {
    onPage();
  }
}());
