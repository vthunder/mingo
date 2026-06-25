// mingo.place primary-IdP provisioning page.
//
// The broker dialog drives us via navigator.id.* (provisioning_api.js):
//   beginProvisioning -> the <handle>@mingo.place identity to provision
//   genKeyPair        -> the dialog generates the keypair, hands us the pubkey
// We sign the pubkey via our /cert_key endpoint (gated on the mingo session +
// handle ownership), then registerCertificate hands the cert back into custody.
// If there's no mingo session, /cert_key 401s and we raiseProvisioningFailure,
// which tells the dialog to fall back to interactive /auth.
(function () {
  "use strict";

  function fail(reason) {
    navigator.id.raiseProvisioningFailure(String(reason || "provisioning failed"));
  }

  navigator.id.beginProvisioning(function (email /*, certDuration */) {
    if (!email) return fail("no email to provision");

    navigator.id.genKeyPair(function (publicKey) {
      // publicKey is a JSON string: { algorithm: 'Ed25519', publicKey: <base64url> }
      var pk;
      try {
        pk = typeof publicKey === "string" ? JSON.parse(publicKey) : publicKey;
      } catch (e) {
        return fail("bad keypair: " + e);
      }

      fetch("/cert_key", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email, pubkey: pk }),
      })
        .then(function (r) {
          if (r.status === 401 || r.status === 403) {
            return fail("NOT_AUTHENTICATED");
          }
          if (!r.ok) {
            return r.text().then(function (t) {
              throw new Error("cert_key " + r.status + " " + t);
            });
          }
          return r.json().then(function (res) {
            navigator.id.registerCertificate(res.cert);
          });
        })
        .catch(fail);
    });
  });
})();
