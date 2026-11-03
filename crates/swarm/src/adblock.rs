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

/// Known-real infra that collides with the DGA/entropy heuristics —
/// CDN names that LOOK hash-y but are legit. Checked BEFORE the
/// shape checks so Discord/media/gaming infra survives.
pub const SAFE_SUFFIXES: &[&str] = &[
    "discord.media", "discord.com", "discord.gg", "discordapp.com",
    "discordapp.net", "discord.dev", "dis.gd",
    // Common CDN/infra that uses encoded host names
    "akamaiedge.net", "akamai.net", "edgesuite.net", "edgekey.net",
    "fastly.net", "cloudfront.net", "azureedge.net", "cdn77.org",
];

/// Is `host` on the safe-infra list (exact or suffix)?
pub fn is_safe(host: &str) -> bool {
    let h = host.trim().to_lowercase();
    let h = h.trim_end_matches('.');
    SAFE_SUFFIXES
        .iter()
        .any(|d| h == *d || h.ends_with(&format!(".{d}")))
}

/// Is `host` an ad/tracker domain (exact or subdomain suffix match,
/// plus a heuristic tail for ad-shaped hosts not in the list)?
pub fn is_ad(host: &str) -> bool {
    let h = host.trim().to_lowercase();
    let h = h.trim_end_matches('.');
    if AD_DOMAINS
        .iter()
        .any(|d| h == *d || h.ends_with(&format!(".{d}")))
    {
        return true;
    }
    // Heuristic — ad-shaped hostnames not on the list. Keep it to
    // REAL ad-serving labels only: telemetry/beacon/tracking are
    // legitimate infra subdomains (discord, browsers, games all
    // use them) — flagging them breaks real apps.
    for l in h.split('.') {
        if matches!(
            l,
            "ads" | "adserver" | "adnxs" | "admetric" | "advert" | "advertising"
        ) {
            return true;
        }
    }
    false
}

/// Is a request path an ad endpoint? (used at the HTTP layer —
/// catches /pagead, /adview, ad-serving paths same-domain DNS can't)
pub fn is_ad_path(path: &str) -> bool {
    let p = path.to_lowercase();
    const PATS: &[&str] = &[
        "/pagead/", "/pagead/", "/ads/", "/adview", "/adserver/",
        "/advert", "/sponsor", "/sponsored/", "/tracking/",
        "/api/stats/ads", "/get_midroll", "/ptracking", "/banner",
        "/doubleclick/", "/adsafeprotected/", "/yieldmanager/",
        "/googlesyndication", "/an/lookup", "/adframe",
    ];
    PATS.iter().any(|pat| p.contains(pat))
}
