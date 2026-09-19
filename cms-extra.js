/* =====================================================================
   TechFix — Custom Code Blocks + Custom Pages runtime
   Loads admin-written code blocks from Firestore and injects them into
   the live site. Also adds custom pages to the navbar menu.
   Collections used:  customBlocks , customPages
   This file does NOT change any existing behaviour.
   ===================================================================== */
(function () {
  'use strict';

  /* ---------- which page am I? ---------- */
  function currentPageId() {
    var path = (location.pathname || '/').toLowerCase();
    // custom dynamic page:  /page.html?p=slug   or   /p/slug
    var m = path.match(/^\/p\/([^\/]+)\/?$/);
    if (m) return 'p:' + decodeURIComponent(m[1]);
    if (path.indexOf('/page.html') === 0 || path.indexOf('page.html') > -1) {
      var q = new URLSearchParams(location.search).get('p');
      if (q) return 'p:' + q.toLowerCase();
    }
    var file = path.split('/').pop().replace(/\.html$/, '');
    if (!file || file === 'index') return 'index';
    return file;
  }

  var PAGE_ID = currentPageId();
  window.TF_PAGE_ID = PAGE_ID;

  /* ---------- run <script> tags inside injected HTML ---------- */
  function activateScripts(container) {
    var scripts = container.querySelectorAll('script');
    for (var i = 0; i < scripts.length; i++) {
      var old = scripts[i];
      var s = document.createElement('script');
      for (var j = 0; j < old.attributes.length; j++) {
        s.setAttribute(old.attributes[j].name, old.attributes[j].value);
      }
      if (!old.src) s.text = old.textContent;
      old.parentNode.replaceChild(s, old);
    }
  }
  window.TF_activateScripts = activateScripts;

  /* ---------- work out where a block should go ---------- */
  function resolveTarget(block) {
    var target = block.target || 'before-footer';
    var el = null, pos = block.position || 'append';

    if (target === 'custom' && block.selector) {
      el = document.querySelector(block.selector);
      return el ? { el: el, pos: pos } : null;
    }
    if (target === 'after-navbar') {
      el = document.querySelector('nav.navbar');
      return el ? { el: el, pos: 'after' } : null;
    }
    if (target === 'before-footer') {
      el = document.querySelector('footer.footer') || document.querySelector('footer');
      return el ? { el: el, pos: 'before' } : { el: document.body, pos: 'append' };
    }
    if (target === 'page-end') {
      return { el: document.body, pos: 'append' };
    }
    if (target === 'main-content') {
      el = document.getElementById('tfPageContent');
      return el ? { el: el, pos: 'append' } : null;
    }
    return { el: document.body, pos: 'append' };
  }

  function placeBlock(host, spot) {
    if (spot.pos === 'before') spot.el.parentNode.insertBefore(host, spot.el);
    else if (spot.pos === 'after') spot.el.parentNode.insertBefore(host, spot.el.nextSibling);
    else if (spot.pos === 'prepend') spot.el.insertBefore(host, spot.el.firstChild);
    else spot.el.appendChild(host);
  }

  function blockAppliesHere(b) {
    var pages = b.pages;
    if (!pages || !pages.length) return false;
    if (pages.indexOf('all') > -1) return true;
    return pages.indexOf(PAGE_ID) > -1;
  }

  /* ---------- render all blocks ---------- */
  function renderBlocks(docs) {
    // remove previously injected blocks (live refresh)
    var old = document.querySelectorAll('[data-tf-block]');
    for (var i = 0; i < old.length; i++) old[i].parentNode.removeChild(old[i]);

    docs.sort(function (a, b) { return (a.order || 0) - (b.order || 0); });

    docs.forEach(function (b) {
      if (b.enabled === false) return;
      if (!blockAppliesHere(b)) return;
      if (!b.code || !b.code.trim()) return;

      var spot = resolveTarget(b);
      if (!spot) return;

      var host = document.createElement('div');
      host.setAttribute('data-tf-block', b.id || '');
      host.className = 'tf-custom-block';
      host.innerHTML = b.code;
      placeBlock(host, spot);
      activateScripts(host);
    });
  }

  /* ---------- custom pages in the navbar ---------- */
  function renderMenuLinks(pages) {
    var navs = document.querySelectorAll('ul.navbar-nav');
    if (!navs.length) return;

    var oldLinks = document.querySelectorAll('li[data-tf-navitem]');
    for (var i = 0; i < oldLinks.length; i++) oldLinks[i].parentNode.removeChild(oldLinks[i]);

    var visible = pages.filter(function (p) {
      return p.published !== false && p.showInMenu === true && p.slug;
    }).sort(function (a, b) { return (a.order || 0) - (b.order || 0); });

    for (var n = 0; n < navs.length; n++) {
      visible.forEach(function (p) {
        var li = document.createElement('li');
        li.className = 'nav-item';
        li.setAttribute('data-tf-navitem', p.slug);
        var a = document.createElement('a');
        a.className = 'nav-link' + (PAGE_ID === 'p:' + p.slug ? ' active' : '');
        a.href = '/p/' + p.slug;
        a.textContent = p.title || p.slug;
        li.appendChild(a);
        navs[n].appendChild(li);
      });
    }
  }

  /* ---------- boot ---------- */
  function boot() {
    if (typeof firebase === 'undefined' || !firebase.apps || !firebase.apps.length) {
      setTimeout(boot, 300);
      return;
    }
    var db = firebase.firestore();

    db.collection('customBlocks').onSnapshot(function (snap) {
      var arr = [];
      snap.forEach(function (d) {
        var o = d.data() || {};
        o.id = d.id;
        arr.push(o);
      });
      renderBlocks(arr);
    }, function (err) { console.warn('Custom blocks skipped', err); });

    db.collection('customPages').onSnapshot(function (snap) {
      var arr = [];
      snap.forEach(function (d) {
        var o = d.data() || {};
        o.id = d.id;
        arr.push(o);
      });
      renderMenuLinks(arr);
    }, function (err) { console.warn('Custom pages skipped', err); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
