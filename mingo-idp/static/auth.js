// mingo.place primary-IdP interactive auth page (fallback).
//
// The broker dialog opens this in a popup when silent provisioning found no
// mingo session. Our supported login flow is SPA-driven (the app re-authenticates
// the external identity and POSTs the assertion to /session/from-assertion), so
// here we simply check whether a mingo session already exists: if so we complete
// authentication (the dialog then retries provisioning silently); otherwise we
// hand control back so the app's own flow can establish the session.
(function () {
  "use strict";
  var msg = document.getElementById("msg");

  navigator.id.beginAuthentication(function (/* email */) {
    fetch("/whoami", { credentials: "include" })
      .then(function (r) { return r.json(); })
      .then(function (w) {
        if (w && w.authenticated) {
          msg.textContent = "Signed in — returning…";
          navigator.id.completeAuthentication();
        } else {
          msg.textContent = "Please sign in from mingo.place, then try again.";
          navigator.id.raiseAuthenticationFailure("no mingo session");
        }
      })
      .catch(function (e) {
        navigator.id.raiseAuthenticationFailure(String(e));
      });
  });
})();
