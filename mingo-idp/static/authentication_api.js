/*
 * BrowserID Authentication API Shim
 * Include this on your primary IdP's authentication page.
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

  // Get parameters from URL
  const params = new URLSearchParams(window.location.search);
  const email = params.get('email');

  // Determine return URL - either from param or referrer
  const returnTo = params.get('return_to') ||
    (document.referrer ? new URL(document.referrer).origin + '/sign_in' : null);

  navigator.id.beginAuthentication = function(callback) {
    if (email) {
      callback(email);
    } else {
      console.error('BrowserID: No email parameter in URL');
    }
  };

  navigator.id.completeAuthentication = function() {
    if (returnTo) {
      window.location.href = returnTo + '#AUTH_RETURN';
    } else {
      console.error('BrowserID: No return URL available');
    }
  };

  navigator.id.raiseAuthenticationFailure = function(reason) {
    console.log('BrowserID: Authentication failed:', reason);
    if (returnTo) {
      window.location.href = returnTo + '#AUTH_RETURN_CANCEL';
    }
  };
})();
