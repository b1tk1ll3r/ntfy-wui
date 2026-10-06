// Applies the stored or preferred color scheme before first paint (loaded synchronously in <head>).
(function () {
  var t = null;
  try { t = localStorage.getItem("ntfywui-theme"); } catch (e) {}
  if (t !== "light" && t !== "dark") {
    t = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", t);
})();
