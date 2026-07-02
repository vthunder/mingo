/*
 * BrowserID Provisioning API Shim
 * Include this on your primary IdP's provisioning page.
 * Copied verbatim from browserid-ng (generic protocol shim).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

(function() {
  'use strict';

  if (typeof navigator.id === 'undefined') {
    navigator.id = {};
  }

  // Simple postMessage channel to parent (broker dialog)
  const channel = {
    _callbacks: {},
    _callId: 0,

    call: function(method, callback) {
      const id = ++this._callId;
      this._callbacks[id] = callback;
      window.parent.postMessage({
        type: 'browserid:provisioning',
        method: method,
        id: id
      }, '*');
    },

    notify: function(method, data) {
      window.parent.postMessage({
        type: 'browserid:provisioning',
        method: method,
        data: data
      }, '*');
    }
  };

  // Handle responses from parent
  window.addEventListener('message', function(event) {
    if (event.data && event.data.type === 'browserid:provisioning:response') {
      const callback = channel._callbacks[event.data.id];
      if (callback) {
        delete channel._callbacks[event.data.id];
        callback(event.data.result);
      }
    }
  });

  navigator.id.beginProvisioning = function(callback) {
    channel.call('beginProvisioning', function(params) {
      callback(params.email, params.cert_duration_s);
    });
  };

  navigator.id.genKeyPair = function(callback) {
    channel.call('genKeyPair', function(result) {
      callback(result.publicKey);
    });
  };

  // `metadata` (optional): private IdP-supplied provisioning metadata forwarded
  // to the dialog over this same-broker channel (NEVER placed in the cert, which
  // is public in assertions). Extensible object; e.g. { subordinate_to } marks a
  // derived identity's controlling parent (mingo-cm8z). Keep in sync with the
  // broker's provisioning_api.js.
  navigator.id.registerCertificate = function(certificate, metadata) {
    channel.notify('registerCertificate', {
      certificate: certificate,
      metadata: metadata || null
    });
  };

  navigator.id.raiseProvisioningFailure = function(reason) {
    channel.notify('raiseProvisioningFailure', { reason: reason });
  };
})();
