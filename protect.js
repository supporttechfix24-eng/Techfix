/* =========================================================
   TechFix — basic front-end protection layer
   Deters casual right-click "view source" / "save as" / copy-paste
   and blocks common developer-tools keyboard shortcuts.
   NOTE: this is a deterrent only — see the note given to the site
   owner. It cannot make client-side HTML/CSS/JS unreadable, since
   the browser must download that code to render the page.
   ========================================================= */
(function () {
  'use strict';

  // Inject "disable text selection" styling (kept here, not in the shared
  // responsive CSS, so pages that opt out of protect.js are unaffected)
  var style = document.createElement('style');
  style.textContent =
    'body{-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none;}' +
    'input,textarea,select,[contenteditable="true"]{-webkit-user-select:text;-moz-user-select:text;-ms-user-select:text;user-select:text;}';
  document.head.appendChild(style);

  function isFormField(el) {
    if (!el) return false;
    var tag = el.tagName ? el.tagName.toLowerCase() : '';
    return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable;
  }

  // Block right-click context menu (except inside form fields)
  document.addEventListener('contextmenu', function (e) {
    if (!isFormField(e.target)) e.preventDefault();
  });

  // Block text selection outside form fields (CSS handles most of this,
  // this is a JS fallback for older browsers / edge cases)
  document.addEventListener('selectstart', function (e) {
    if (!isFormField(e.target)) e.preventDefault();
  });

  // Block dragging images/links out of the page
  document.addEventListener('dragstart', function (e) {
    if (!isFormField(e.target)) e.preventDefault();
  });

  // Block common "view source" / dev tools / save page shortcuts
  document.addEventListener('keydown', function (e) {
    var key = (e.key || '').toLowerCase();

    // F12 - Dev Tools
    if (e.key === 'F12') { e.preventDefault(); return; }

    // Ctrl/Cmd + U - View Source
    if ((e.ctrlKey || e.metaKey) && key === 'u') { e.preventDefault(); return; }

    // Ctrl/Cmd + S - Save Page
    if ((e.ctrlKey || e.metaKey) && key === 's') { e.preventDefault(); return; }

    // Ctrl/Cmd + Shift + I/J/C - Dev Tools panels
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (key === 'i' || key === 'j' || key === 'c')) {
      e.preventDefault();
      return;
    }
  });
})();
