// mingo.place primary-IdP interactive auth page (fallback).
//
// The broker dialog opens this in a popup when silent provisioning found no
// mingo session. Signed in → complete authentication (the dialog retries
// provisioning silently). Signed out → hand control back with a non-revealing
// message; the browserid account, once authenticated, drives the parent auth for
// a subordinate identity (see mingo-cm8z). We never disclose the owner mapping.
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
          msg.textContent = "Please sign in to browserid first, then try again.";
          navigator.id.raiseAuthenticationFailure("no mingo session");
        }
      })
      .catch(function (e) {
        navigator.id.raiseAuthenticationFailure(String(e));
      });
  });
})();
