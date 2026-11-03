//! Shared ad/tracker domain blocklist — suffix-matched so
//! `ads.foo.net` dies on the `foo.net` entry. Network-level blocking:
//! the request never leaves the machine. Covers the ad-network layer
//! (display/tracker calls); same-domain ads (YouTube/sponsored posts)
//! can't be separated by domain — honest limit.

/// Common ad/tracker network domains.
pub const AD_DOMAINS: &[&str] = &[
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "googletagservices.com", "adservice.google.com", "adnxs.com",
    "advertising.com", "adsrvr.org", "adtechus.com", "adform.net",
    "openx.net", "pubmatic.com", "rubiconproject.com", "taboola.com",
    "outbrain.com", "criteo.com", "criteo.net", "amazon-adsystem.com",
    "moatads.com", "scorecardresearch.com", "quantserve.com",
    "ads.yahoo.com", "ad.doubleclick.net", "pagead2.googlesyndication.com",
    "adswizz.com", "zedo.com", "yieldmanager.com", "media.net",
    "contextweb.com", "bidswitch.net", "casalemedia.com", "indexexchange.com",
    "turn.com", "flashtalking.com", "smartadserver.com", "bluekai.com",
    "exelator.com", "eyeota.net", "sharethrough.com", "teads.tv",
    "revcontent.com", "mgid.com", "zemanta.com", "admob.com",
    "inmobi.com", "appsflyer.com", "branch.io", "adjust.com",
    "mixpanel.com", "segment.com", "segment.io", "hotjar.com",
    "fullstory.com", "logrocket.com", "luckyorange.com", "mouseflow.com",
    "ads-twitter.com", "static.ads-twitter.com", "analytics.twitter.com",
    "ads.linkedin.com", "snap.licdn.com", "ads.pinterest.com",
    "ads.tiktok.com", "analytics.tiktok.com", "adsapi.tiktok.com",
    "ads.reddit.com", "events.reddit.com", "ads.snapchat.com",
    "ads.api.snapchat.com", "ads.youtube.com",
];

/// Is `host` an ad/tracker domain (exact or subdomain suffix match)?
pub fn is_ad(host: &str) -> bool {
    let h = host.trim().to_lowercase();
    let h = h.trim_end_matches('.');
    AD_DOMAINS
        .iter()
        .any(|d| h == *d || h.ends_with(&format!(".{d}")))
}
