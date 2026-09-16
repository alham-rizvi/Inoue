# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Additional technology signatures for widely used modern services that
weren't yet in the catalog, plus version-capture upgrades merged onto a
handful of existing high-prevalence entries.

Every entry here uses a detection signal (a header name, a meta generator
tag, a well-known script CDN path, a cookie name) that's genuinely
documented, common, public behavior of that technology - not a guessed
or fabricated value. Where the underlying tech is known to expose a
version number in that same signal (meta generator tags are the most
common case - WordPress, Ghost, Drupal-style CMSs routinely print
"ProductName X.Y.Z"), the pattern includes a capturing group so the
scanner reports a real version instead of "unknown". Where a technology
doesn't expose version passively (most JS libraries loaded from a CDN
with a hashed/minified filename, most SaaS widgets), the entry is
presence-only - no version claim is invented to pad a capture-group count.

Merged into `SIGNATURES` the same way `EXTENDED_SIGNATURES` is: a name
that already exists gets its detection surface extended (e.g. adding a
version-capturing meta pattern to a signature that previously only had
non-versioned html markers); a new name is added outright.
"""

MODERN_SIGNATURES: dict = {
    # ---- JS/backend frameworks ------------------------------------------------
    # (Express is already covered by the existing "Express.js" core signature -
    # not duplicated here.)
    "Next.js": {"html": [r"/_next/static/", r"__NEXT_DATA__"], "category": "JS Framework"},
    "Nuxt.js": {"html": [r"/_nuxt/", r"__NUXT__"], "category": "JS Framework"},
    "SvelteKit": {"html": [r"/_app/immutable/"], "category": "JS Framework"},
    "Astro": {"meta": {"generator": r"Astro\s*v?(\d+[\d.]+)?"}, "category": "JS Framework"},
    "Gatsby": {"meta": {"generator": r"Gatsby\s*(\d+[\d.]+)?"}, "html": [r"___gatsby"], "category": "JS Framework"},
    "Remix": {"html": [r"__remixContext"], "category": "JS Framework"},
    "Docusaurus": {"meta": {"generator": r"Docusaurus\s*v?(\d+[\d.]+)?"}, "category": "Static Site Generator"},

    # ---- Static site generators / docs ------------------------------------------------
    "Hugo": {"meta": {"generator": r"Hugo\s*(\d+[\d.]+)?"}, "category": "Static Site Generator"},
    "VuePress": {"meta": {"generator": r"VuePress\s*(\d+[\d.]+)?"}, "category": "Static Site Generator"},
    "Zola": {"meta": {"generator": r"Zola\s*v?(\d+[\d.]+)?"}, "category": "Static Site Generator"},
    "Pelican": {"meta": {"generator": r"Pelican(?:/(\d+[\d.]+))?"}, "category": "Static Site Generator"},
    "Middleman": {"meta": {"generator": r"Middleman(?:\s(\d+[\d.]+))?"}, "category": "Static Site Generator"},
    "Publii": {"meta": {"generator": r"Publii(?:\s(\d+[\d.]+))?"}, "category": "Static Site Generator"},
    "MkDocs": {"meta": {"generator": r"mkdocs(?:-(\d+[\d.]+))?"}, "category": "Documentation"},
    "Sphinx": {"meta": {"generator": r"Sphinx\s*(\d+[\d.]+)?"}, "category": "Documentation"},
    "Read the Docs": {"html": [r"readthedocs"], "category": "Documentation"},
    "Storybook": {"html": [r"sb-preview", r"__STORYBOOK"], "category": "Documentation"},
    "Swagger UI": {"html": [r"swagger-ui"], "category": "Documentation"},
    "Redoc": {"html": [r"<redoc", r"redoc\.standalone"], "category": "Documentation"},
    "GraphQL Playground": {"html": [r"graphql-playground"], "category": "Documentation"},

    # ---- CMS ------------------------------------------------
    "Ghost": {"meta": {"generator": r"Ghost\s*(\d+[\d.]+)?"}, "category": "CMS"},
    "Webflow": {"meta": {"generator": r"Webflow"}, "category": "CMS"},
    "Framer": {"meta": {"generator": r"Framer"}, "html": [r"framerusercontent\.com"], "category": "CMS"},
    "Carrd": {"meta": {"generator": r"Carrd"}, "category": "CMS"},
    "Umbraco": {"headers": {"X-Umbraco-Version": r"(\d+[\d.]+)"}, "category": "CMS"},
    "Craft CMS": {"cookies": ["CraftSessionId"], "category": "CMS"},
    "SilverStripe": {"headers": {"X-Generator": r"SilverStripe(?:\s(\d+[\d.]+))?"}, "category": "CMS"},
    "Contao": {"meta": {"generator": r"Contao"}, "category": "CMS"},
    "Concrete CMS": {"meta": {"generator": r"Concrete\s?CMS(?:\s(\d+[\d.]+))?|concrete5"}, "category": "CMS"},
    "ExpressionEngine": {"meta": {"generator": r"ExpressionEngine(?:\s(\d+[\d.]+))?"}, "category": "CMS"},
    "TYPO3": {"meta": {"generator": r"TYPO3(?:\s(\d+[\d.]+))?"}, "category": "CMS"},
    "dotCMS": {"headers": {"X-Powered-By": r"dotCMS"}, "category": "CMS"},
    "Bitrix": {"meta": {"generator": r"Bitrix"}, "category": "CMS"},
    "Kirby": {"meta": {"generator": r"Kirby(?:\s(\d+[\d.]+))?"}, "category": "CMS"},
    "ProcessWire": {"meta": {"generator": r"ProcessWire(?:\s(\d+[\d.]+))?"}, "category": "CMS"},
    "Textpattern": {"meta": {"generator": r"Textpattern"}, "category": "CMS"},
    "Grav": {"meta": {"generator": r"GravCMS|Grav(?:\s(\d+[\d.]+))?"}, "category": "CMS"},
    "Statamic": {"cookies": ["statamic_session"], "category": "CMS"},
    "Duda": {"html": [r"irp\.cdn-website\.com", r"\bduda\b"], "category": "CMS"},
    "Weebly": {"html": [r"cdn2\.editmysite\.com"], "category": "CMS"},
    "Jimdo": {"html": [r"jimdo(?:statics)?\.com"], "category": "CMS"},
    "Tilda": {"meta": {"generator": r"Tilda"}, "category": "CMS"},
    "Readymag": {"meta": {"generator": r"Readymag"}, "category": "CMS"},

    # ---- E-commerce ------------------------------------------------
    "WooCommerce": {"cookies": ["woocommerce_cart_hash", "woocommerce_items_in_cart"], "html": [r"woocommerce"], "category": "E-commerce"},
    "Magento": {"html": [r"Mage\.Cookies", r"data-mage-init"], "cookies": ["mage-cache-sessid"], "category": "E-commerce"},
    "BigCommerce": {"html": [r"cdn11\.bigcommerce\.com"], "category": "E-commerce"},
    "PrestaShop": {"meta": {"generator": r"PrestaShop(?:\s(\d+[\d.]+))?"}, "category": "E-commerce"},
    "OpenCart": {"cookies": ["OCSESSID"], "category": "E-commerce"},
    "Salesforce Commerce Cloud": {"cookies": ["dwsid", "dwanonymous_"], "category": "E-commerce"},
    "Shopware": {"meta": {"generator": r"Shopware(?:\s(\d+[\d.]+))?"}, "category": "E-commerce"},
    "Ecwid": {"html": [r"app\.ecwid\.com"], "category": "E-commerce"},
    "Snipcart": {"html": [r"cdn\.snipcart\.com"], "category": "E-commerce"},
    "Foxy.io": {"html": [r"cdn\.foxycart\.com"], "category": "E-commerce"},

    # ---- WordPress plugin/theme ecosystem ------------------------------------------------
    "Elementor": {"html": [r"elementor"], "category": "WordPress Plugin"},
    "Divi": {"html": [r"et_pb_"], "category": "WordPress Plugin"},
    "Beaver Builder": {"html": [r"fl-builder"], "category": "WordPress Plugin"},
    "WPBakery": {"html": [r"wpb_(?:row|column|content)"], "category": "WordPress Plugin"},
    "Yoast SEO": {"html": [r"Yoast SEO"], "meta": {"generator": r"Yoast SEO(?:\s(\d+[\d.]+))?"}, "category": "WordPress Plugin"},
    "Rank Math": {"html": [r"Rank Math"], "category": "WordPress Plugin"},
    "All in One SEO": {"html": [r"aioseo"], "category": "WordPress Plugin"},
    "Contact Form 7": {"html": [r"wpcf7"], "category": "WordPress Plugin"},
    "Gravity Forms": {"html": [r"gform_wrapper"], "category": "WordPress Plugin"},
    "WPForms": {"html": [r"wpforms"], "category": "WordPress Plugin"},
    "Ninja Forms": {"html": [r"nf-form"], "category": "WordPress Plugin"},
    "MemberPress": {"html": [r"memberpress"], "category": "WordPress Plugin"},
    "LearnDash": {"html": [r"learndash"], "category": "WordPress Plugin"},
    "bbPress": {"html": [r"bbpress"], "category": "WordPress Plugin"},
    "BuddyPress": {"html": [r"buddypress"], "category": "WordPress Plugin"},
    "Jetpack": {"html": [r"jetpack"], "category": "WordPress Plugin"},
    "WP Rocket": {"html": [r"WP Rocket"], "category": "WordPress Plugin"},
    "W3 Total Cache": {"html": [r"Performance optimized by W3 Total Cache"], "category": "WordPress Plugin"},
    "WP Super Cache": {"html": [r"WP Super Cache"], "category": "WordPress Plugin"},
    "Autoptimize": {"html": [r"autoptimize"], "category": "WordPress Plugin"},

    # ---- Analytics / tag managers ------------------------------------------------
    "Google Tag Manager": {"scripts": [r"googletagmanager\.com/gtm\.js"], "category": "Analytics"},
    "Google Analytics 4": {"scripts": [r"googletagmanager\.com/gtag/js", r"google-analytics\.com/analytics\.js"], "category": "Analytics"},
    "Mixpanel": {"scripts": [r"cdn\.mxpnl\.com"], "category": "Analytics"},
    "Amplitude": {"scripts": [r"cdn\.amplitude\.com"], "category": "Analytics"},
    "Hotjar": {"scripts": [r"static\.hotjar\.com"], "category": "Analytics"},
    "FullStory": {"scripts": [r"fullstory\.com/s/fs\.js"], "category": "Analytics"},
    "Crazy Egg": {"scripts": [r"script\.crazyegg\.com"], "category": "Analytics"},
    "Optimizely": {"scripts": [r"cdn\.optimizely\.com"], "category": "Analytics"},
    "VWO": {"scripts": [r"dev\.visualwebsiteoptimizer\.com"], "category": "Analytics"},
    "Microsoft Clarity": {"scripts": [r"clarity\.ms/tag"], "category": "Analytics"},
    "Heap Analytics": {"scripts": [r"cdn\.heapanalytics\.com"], "category": "Analytics"},
    "Chartbeat": {"scripts": [r"static\.chartbeat\.com"], "category": "Analytics"},
    "Quantcast": {"scripts": [r"edge\.quantserve\.com"], "category": "Analytics"},
    "comScore": {"scripts": [r"sb\.scorecardresearch\.com"], "category": "Analytics"},
    "PostHog": {"scripts": [r"app\.posthog\.com", r"posthog-js"], "category": "Analytics"},
    "Umami": {"html": [r"data-website-id"], "scripts": [r"umami\.js"], "category": "Analytics"},

    # ---- Ad pixels ------------------------------------------------
    "LinkedIn Insight Tag": {"scripts": [r"snap\.licdn\.com/li\.lms-analytics"], "category": "Analytics"},
    "Twitter Ads Pixel": {"scripts": [r"static\.ads-twitter\.com"], "category": "Analytics"},
    "Pinterest Tag": {"scripts": [r"s\.pinimg\.com/ct/core\.js"], "category": "Analytics"},
    "Snapchat Pixel": {"scripts": [r"sc-static\.net/scevent\.min\.js"], "category": "Analytics"},
    "TikTok Pixel": {"scripts": [r"analytics\.tiktok\.com/i18n/pixel"], "category": "Analytics"},
    "Reddit Pixel": {"scripts": [r"events\.redditmedia\.com/rp\.js"], "category": "Analytics"},
    "Bing Ads UET": {"scripts": [r"bat\.bing\.com/bat\.js"], "category": "Analytics"},

    # ---- Chat / support widgets ------------------------------------------------
    "Intercom": {"html": [r"window\.Intercom"], "scripts": [r"widget\.intercom\.io"], "category": "Collaboration / CRM / Chat"},
    "Zendesk Widget": {"scripts": [r"static\.zdassets\.com"], "category": "Collaboration / CRM / Chat"},
    "Drift": {"scripts": [r"js\.driftt\.com"], "category": "Collaboration / CRM / Chat"},
    "Crisp": {"scripts": [r"client\.crisp\.chat"], "category": "Collaboration / CRM / Chat"},
    "Tawk.to": {"scripts": [r"embed\.tawk\.to"], "category": "Collaboration / CRM / Chat"},
    "LiveChat": {"scripts": [r"cdn\.livechatinc\.com"], "category": "Collaboration / CRM / Chat"},
    "Freshchat": {"scripts": [r"wchat\.freshchat\.com"], "category": "Collaboration / CRM / Chat"},
    "Olark": {"scripts": [r"static\.olark\.com"], "category": "Collaboration / CRM / Chat"},
    "Userlike": {"scripts": [r"userlike\.com/widget"], "category": "Collaboration / CRM / Chat"},

    # ---- Payments ------------------------------------------------
    "PayPal": {"scripts": [r"paypalobjects\.com", r"paypal\.com/sdk/js"], "category": "Payments"},
    "Square": {"scripts": [r"squarecdn\.com", r"js\.squareup\.com"], "category": "Payments"},
    "Braintree": {"scripts": [r"js\.braintreegateway\.com"], "category": "Payments"},
    "Adyen": {"scripts": [r"checkoutshopper-live\.adyen\.com"], "category": "Payments"},
    "Klarna": {"scripts": [r"x\.klarnacdn\.net"], "category": "Payments"},
    "Afterpay": {"scripts": [r"js\.afterpay\.com"], "category": "Payments"},
    "Razorpay": {"scripts": [r"checkout\.razorpay\.com"], "category": "Payments"},
    "Recurly": {"scripts": [r"js\.recurly\.com"], "category": "Payments"},
    "Chargebee": {"scripts": [r"js\.chargebee\.com"], "category": "Payments"},

    # ---- Auth / identity ------------------------------------------------
    "Auth0": {"scripts": [r"cdn\.auth0\.com"], "category": "Identity / Auth"},
    "Clerk": {"scripts": [r"clerk\.[a-z0-9.]*\.(?:dev|com)"], "cookies": ["__client"], "category": "Identity / Auth"},
    "Okta": {"cookies": ["okta-oauth-state", "okta-oauth-nonce"], "scripts": [r"okta\.com"], "category": "Identity / Auth"},
    "Firebase Auth": {"scripts": [r"gstatic\.com/firebasejs"], "category": "Identity / Auth"},

    # ---- Search ------------------------------------------------
    "Algolia": {"scripts": [r"cdn\.jsdelivr\.net/npm/algoliasearch", r"\.algolia(?:net)?\.net"], "category": "Search Engine"},
    "Algolia DocSearch": {"scripts": [r"docsearch\.js"], "category": "Search Engine"},

    # ---- Monitoring / error tracking ------------------------------------------------
    "New Relic Browser": {"scripts": [r"js-agent\.newrelic\.com"], "html": [r"NREUM"], "category": "Monitoring"},
    "Datadog RUM": {"html": [r"DD_RUM"], "scripts": [r"datadoghq-browser-agent"], "category": "Monitoring"},
    "Sentry": {"scripts": [r"browser\.sentry-cdn\.com", r"js\.sentry-cdn\.com"], "html": [r"Sentry\.init"], "category": "Monitoring"},
    "LogRocket": {"scripts": [r"cdn\.lr-ingest\.io", r"cdn\.logrocket\.io"], "category": "Monitoring"},
    "Rollbar": {"scripts": [r"cdn\.rollbar\.com"], "category": "Monitoring"},
    "Bugsnag": {"scripts": [r"d2wy8f7a9ursnm\.cloudfront\.net/bugsnag"], "category": "Monitoring"},
    "Raygun": {"scripts": [r"cdn\.raygun\.io"], "category": "Monitoring"},

    # ---- Consent / captcha ------------------------------------------------
    "Cloudflare Turnstile": {"scripts": [r"challenges\.cloudflare\.com/turnstile"], "category": "Security / Network"},
    "reCAPTCHA": {"scripts": [r"google\.com/recaptcha", r"gstatic\.com/recaptcha"], "category": "Security / Network"},
    "hCaptcha": {"scripts": [r"hcaptcha\.com"], "category": "Security / Network"},
    "OneTrust": {"scripts": [r"cdn\.cookielaw\.org"], "category": "Security / Network"},
    "Cookiebot": {"scripts": [r"consent\.cookiebot\.com"], "category": "Security / Network"},
    "Termly": {"scripts": [r"app\.termly\.io"], "category": "Security / Network"},

    # ---- Email / marketing ------------------------------------------------
    "Klaviyo": {"scripts": [r"static\.klaviyo\.com"], "category": "Marketing"},
    "Mailchimp": {"scripts": [r"chimpstatic\.com", r"list-manage\.com"], "category": "Marketing"},
    "ConvertKit": {"scripts": [r"convertkit\.com"], "category": "Marketing"},
    "ActiveCampaign": {"scripts": [r"activehosted\.com"], "category": "Marketing"},
    "Braze": {"scripts": [r"js\.appboycdn\.com"], "category": "Marketing"},
    "OneSignal": {"scripts": [r"cdn\.onesignal\.com"], "category": "Marketing"},

    # ---- Realtime / infra ------------------------------------------------
    "Pusher": {"scripts": [r"js\.pusher\.com"], "category": "Realtime"},
    "Ably": {"scripts": [r"cdn\.ably\.io", r"cdn\.ably-realtime\.com"], "category": "Realtime"},
    "Twilio": {"scripts": [r"sdk\.twilio\.com"], "category": "Realtime"},
    "Supabase": {"html": [r"\.supabase\.co"], "category": "Cloud / Infrastructure"},
    "Netlify": {"headers": {"x-nf-request-id": None}, "category": "Hosting"},
    "Fly.io": {"headers": {"fly-request-id": None}, "category": "Hosting"},
    "Heroku": {"headers": {"Via": r"vegur"}, "category": "Hosting"},

    # ---- Scheduling / forms ------------------------------------------------
    "Calendly": {"scripts": [r"assets\.calendly\.com"], "category": "Collaboration / CRM / Chat"},
    "Typeform": {"scripts": [r"embed\.typeform\.com"], "category": "Collaboration / CRM / Chat"},

    # ---- Experimentation / feature flags ------------------------------------------------
    "Google Optimize": {"scripts": [r"googleoptimize\.com"], "category": "Analytics"},
    "AB Tasty": {"scripts": [r"try\.abtasty\.com"], "category": "Analytics"},
    "Kameleoon": {"scripts": [r"kameleoon\.com"], "category": "Analytics"},
    "Split.io": {"scripts": [r"sdk\.split\.io"], "category": "Analytics"},
    "LaunchDarkly": {"scripts": [r"app\.launchdarkly\.com", r"clientstream\.launchdarkly\.com"], "category": "Analytics"},
    "Flagsmith": {"scripts": [r"cdn\.flagsmith\.com"], "category": "Analytics"},

    # ---- Fonts / asset CDNs ------------------------------------------------
    "Google Fonts": {"html": [r"fonts\.googleapis\.com"], "category": "CDN"},
    "Adobe Fonts": {"scripts": [r"use\.typekit\.net"], "category": "CDN"},
    "jsDelivr": {"scripts": [r"cdn\.jsdelivr\.net"], "category": "CDN"},
    "unpkg": {"scripts": [r"unpkg\.com"], "category": "CDN"},
    "cdnjs": {"scripts": [r"cdnjs\.cloudflare\.com"], "category": "CDN"},
}
