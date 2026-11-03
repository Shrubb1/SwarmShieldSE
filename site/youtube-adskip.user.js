// ==UserScript==
// @name         SwarmShieldSE — YouTube ad-skip
// @namespace    swarmshield
// @version      1.0
// @description  Browser-layer ad blocking — the only layer that can
//               kill YouTube mid-video ads (they're same-domain as
//               content, invisible to DNS/network blocking). Skips
//               preroll/midroll ads and hides ad containers.
// @match        *://*.youtube.com/*
// @run-at       document-start
// ==/UserScript==
(function () {
  'use strict';
  // 1. Speed-run the ad: max out the ad element's playback so the
  //    "skip" button appears + the ad finishes instantly.
  const fastForward = () => {
    const vid = document.querySelector('video');
    if (vid && document.querySelector('.ad-showing')) {
      vid.playbackRate = 16;
      vid.muted = true;
      if (isFinite(vid.duration)) vid.currentTime = vid.duration - 0.1;
    }
  };
  // 2. Click skip whenever it appears.
  const clickSkip = () => {
    document
      .querySelectorAll('.ytp-skip-ad-button, .ytp-ad-skip-button, .ytp-ad-skip-button-modern')
      .forEach((b) => b.click());
  };
  // 3. Kill the overlay containers (banner cards, ad slots in feed).
  const hideOverlays = () => {
    document
      .querySelectorAll(
        'ytd-display-ad-renderer, ytd-promoted-sparkles-web-renderer, .ytp-ad-overlay-container, ytd-companion-slot-renderer, ytd-action-companion-ad-renderer'
      )
      .forEach((el) => el.remove());
  };
  setInterval(() => {
    fastForward();
    clickSkip();
    hideOverlays();
  }, 500);
})();
