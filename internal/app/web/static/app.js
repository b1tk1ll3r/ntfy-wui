// ntfywui – progressive enhancements. Every feature works without JS except
// conveniences (copy, generate, filter, preview). No inline handlers (strict CSP).
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  var on = function (type, sel, fn) {
    document.addEventListener(type, function (e) {
      var el = e.target.closest && e.target.closest(sel);
      if (el) fn(e, el);
    });
  };

  // ---------- Theme ----------
  on("click", "[data-theme-toggle]", function () {
    var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("ntfywui-theme", next); } catch (e) {}
  });

  // ---------- Mobile navigation ----------
  on("click", "[data-nav-toggle]", function () { document.body.classList.toggle("nav-open"); });
  on("click", "[data-nav-close]", function () { document.body.classList.remove("nav-open"); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") document.body.classList.remove("nav-open");
  });

  // ---------- Alerts ----------
  on("click", "[data-dismiss]", function (e, el) {
    var a = el.closest(".alert");
    if (a) a.remove();
  });
  $$(".alert[data-autohide].alert-success, .alert[data-autohide].alert-info").forEach(function (a) {
    setTimeout(function () {
      a.classList.add("is-hiding");
      setTimeout(function () { a.remove(); }, 350);
    }, 6000);
  });

  // ---------- Confirm dialog for destructive forms ----------
  var confirmDlg = $("#confirm-dialog");
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!form.matches || !form.matches("form[data-confirm]") || form.dataset.confirmed === "1") return;
    if (!confirmDlg || typeof confirmDlg.showModal !== "function") {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
      return;
    }
    e.preventDefault();
    $(".confirm-msg", confirmDlg).textContent = form.dataset.confirm;
    $(".confirm-ok", confirmDlg).textContent = form.dataset.confirmOk || "Bestätigen";
    confirmDlg.returnValue = "";
    confirmDlg.showModal();
    $(".btn-ghost", confirmDlg).focus();
    confirmDlg.addEventListener("close", function handler() {
      confirmDlg.removeEventListener("close", handler);
      if (confirmDlg.returnValue === "ok") {
        form.dataset.confirmed = "1";
        if (form.requestSubmit) form.requestSubmit(); else form.submit();
      }
    });
  }, true);

  // ---------- Prevent double submits ----------
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (e.defaultPrevented || !form.matches || !form.matches("form[data-once], form[data-confirm]")) return;
    if (form.dataset.busy === "1") { e.preventDefault(); return; }
    form.dataset.busy = "1";
    $$("button[type=submit]", form).forEach(function (b) { b.classList.add("is-busy"); });
    // Re-enable after a while in case the navigation is cancelled.
    setTimeout(function () {
      form.dataset.busy = "";
      $$("button[type=submit]", form).forEach(function (b) { b.classList.remove("is-busy"); });
    }, 8000);
  });

  // ---------- Dialogs ----------
  on("click", "[data-dialog-open]", function (e, el) {
    var dlg = $(el.dataset.dialogOpen);
    if (!dlg) return;
    $$("[data-fill]", dlg).forEach(function (inp) {
      var v = el.getAttribute("data-fill-" + inp.dataset.fill);
      if (v !== null) inp.value = v;
    });
    $$("[data-fill-text]", dlg).forEach(function (t) {
      var v = el.getAttribute("data-fill-" + t.dataset.fillText);
      if (v !== null) t.textContent = v;
    });
    dlg.showModal();
    var first = $("input:not([type=hidden]):not([type=radio]), select, textarea", dlg);
    if (first) first.focus();
  });
  on("click", "[data-dialog-close]", function (e, el) {
    var dlg = el.closest("dialog");
    if (dlg) dlg.close();
  });
  // Close on backdrop click.
  $$("dialog.dialog").forEach(function (dlg) {
    dlg.addEventListener("click", function (e) {
      if (e.target === dlg) dlg.close("cancel");
    });
  });
  // Open a dialog via URL hash (e.g. /users#new).
  if (location.hash) {
    var hashDlg = $('dialog[data-dialog-hash="' + location.hash.slice(1).replace(/[^a-z0-9_-]/gi, "") + '"]');
    if (hashDlg) {
      hashDlg.showModal();
      history.replaceState(null, "", location.pathname + location.search);
    }
  }

  // ---------- Clickable table rows ----------
  on("click", "tr[data-href]", function (e, tr) {
    if (e.target.closest("a, button, input, select, form, label")) return;
    window.location.href = tr.dataset.href;
  });

  // ---------- Clipboard ----------
  function copyText(text, btn) {
    var done = function () {
      if (!btn) return;
      var label = btn.querySelector("span");
      var prev = label ? label.textContent : btn.title;
      if (label) label.textContent = "Kopiert!"; else btn.title = "Kopiert!";
      btn.classList.add("is-copied");
      setTimeout(function () {
        if (label) label.textContent = prev; else btn.title = prev;
        btn.classList.remove("is-copied");
      }, 1600);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else {
      fallbackCopy(text);
      done();
    }
  }
  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.className = "sr-only";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) {}
    ta.remove();
  }
  on("click", "[data-copy]", function (e, el) { copyText(el.dataset.copy, el); });
  on("click", "[data-copy-from]", function (e, el) {
    var src = $(el.dataset.copyFrom);
    if (src && src.value) copyText(src.value, el);
  });

  // ---------- Passwords ----------
  on("click", "[data-reveal]", function (e, el) {
    var inp = $(el.dataset.reveal);
    if (!inp) return;
    inp.type = inp.type === "password" ? "text" : "password";
    el.setAttribute("aria-pressed", inp.type === "text" ? "true" : "false");
  });
  on("click", "[data-genpass]", function (e, el) {
    var inp = $(el.dataset.genpass);
    if (!inp) return;
    var alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    var bytes = new Uint32Array(20);
    window.crypto.getRandomValues(bytes);
    var out = "";
    for (var i = 0; i < bytes.length; i++) out += alphabet[bytes[i] % alphabet.length];
    inp.value = out;
    inp.type = "text";
    inp.dispatchEvent(new Event("input", { bubbles: true }));
    inp.focus();
    inp.select();
  });
  on("input", "[data-strength]", function (e, inp) {
    var meter = inp.parentNode.querySelector(".strength");
    if (!meter) return;
    var v = inp.value, s = 0;
    if (v.length >= 8) s++;
    if (v.length >= 12) s++;
    if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++;
    if (/\d/.test(v) && /[^A-Za-z0-9]/.test(v) || v.length >= 16) s++;
    meter.dataset.score = v ? Math.max(1, s) : "";
  });
  on("input", "[data-match]", function (e, inp) {
    var other = $(inp.dataset.match);
    inp.setCustomValidity(other && inp.value !== other.value ? "Die Passwörter stimmen nicht überein." : "");
  });

  // ---------- Auto-submit ----------
  on("change", "select[data-autosubmit]", function (e, el) {
    if (el.form) el.form.requestSubmit ? el.form.requestSubmit() : el.form.submit();
  });
  on("input", "[data-autosubmit-len]", function (e, el) {
    var digits = el.value.replace(/\D/g, "");
    if (digits.length === parseInt(el.dataset.autosubmitLen, 10) && el.form && !el.form.dataset.busy) {
      el.form.requestSubmit ? el.form.requestSubmit() : el.form.submit();
    }
  });

  // ---------- Table filter ----------
  function applyFilter(input) {
    var table = $(input.dataset.filter);
    if (!table) return;
    var q = input.value.trim().toLowerCase();
    var rows = $$("tbody tr:not(.filter-empty):not(.empty-row)", table);
    var shown = 0;
    rows.forEach(function (r) {
      var match = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
      r.hidden = !match;
      if (match) shown++;
    });
    var empty = $("tr.filter-empty", table);
    if (empty) empty.hidden = !(rows.length && shown === 0);
    var counter = $('[data-filter-count="' + input.dataset.filter + '"]');
    if (counter) counter.textContent = (q ? shown + " von " + rows.length : rows.length) + " Einträge";
  }
  on("input", "input[data-filter]", function (e, el) { applyFilter(el); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "/" && !e.target.closest("input, textarea, select, [contenteditable]")) {
      var f = $("input[data-filter], .search input");
      if (f) { e.preventDefault(); f.focus(); }
    }
  });

  // ---------- Chart tooltips ----------
  var tip = $("#tooltip");
  function showTip(el) {
    if (!tip) return;
    var r = el.getBoundingClientRect();
    tip.textContent = el.dataset.tip;
    tip.hidden = false;
    tip.style.left = r.left + r.width / 2 + "px";
    tip.style.top = r.top + "px";
  }
  function hideTip() { if (tip) tip.hidden = true; }
  on("mouseover", "[data-tip]", function (e, el) { showTip(el); });
  on("mouseout", "[data-tip]", hideTip);
  on("focusin", "[data-tip]", function (e, el) { showTip(el); });
  on("focusout", "[data-tip]", hideTip);
  window.addEventListener("scroll", hideTip, { passive: true });

  // ---------- Publish preview ----------
  var preview = $("#notif-preview");
  if (preview) {
    var emoji = {
      warning: "⚠️", rotating_light: "🚨", white_check_mark: "✅", heavy_check_mark: "✔️", x: "❌",
      tada: "🎉", fire: "🔥", skull: "💀", bell: "🔔", loudspeaker: "📢", no_entry: "⛔", "+1": "👍",
      "-1": "👎", partying_face: "🥳", computer: "💻", floppy_disk: "💾", lock: "🔒", key: "🔑",
      rocket: "🚀", bug: "🐛", zap: "⚡", sunny: "☀️", cloud: "☁️", house: "🏠", email: "📧", calendar: "📅"
    };
    var form = $("#publish-form");
    var update = function () {
      var get = function (n) { var el = form.elements[n]; return el ? el.value : ""; };
      var topic = get("topic").trim() || "topic";
      $$('[data-out="topic"]').forEach(function (o) { o.textContent = topic; });
      var tags = get("tags").split(",").map(function (t) { return t.trim(); }).filter(Boolean);
      var emo = tags.map(function (t) { return emoji[t] || ""; }).join("");
      $('[data-out="tags"]', preview).textContent = emo;
      $('[data-out="title"]', preview).textContent = get("title");
      $('[data-out="message"]', preview).textContent = get("message") || "Deine Nachricht erscheint hier.";
      var prio = form.querySelector("input[name=priority]:checked");
      preview.dataset.prio = prio ? prio.value : "3";
      var plain = tags.filter(function (t) { return !emoji[t]; });
      if (plain.length) $('[data-out="message"]', preview).textContent += "\nTags: " + plain.join(", ");
    };
    form.addEventListener("input", update);
    form.addEventListener("change", update);
    update();
  }
})();
