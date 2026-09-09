"""
Tech stack fingerprint signatures.
Each entry maps a technology to detection rules across headers, cookies, HTML, scripts, meta tags, etc.
"""

import re
from re import Pattern
from typing import Any

from fingerprints.extended_catalog import EXTENDED_SIGNATURES

SIGNATURES = {
    # --- Web Servers ---
    "Apache": {
        "headers": {"Server": r"Apache(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "Nginx": {
        "headers": {"Server": r"nginx(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "IIS": {
        "headers": {"Server": r"Microsoft-IIS(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "LiteSpeed": {
        "headers": {"Server": r"LiteSpeed"},
        "category": "Web Server",
    },
    "Caddy": {
        "headers": {"Server": r"Caddy"},
        "category": "Web Server",
    },
    "OpenResty": {
        "headers": {"Server": r"openresty(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "Gunicorn": {
        "headers": {"Server": r"gunicorn(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "Werkzeug": {
        "headers": {"Server": r"Werkzeug(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "Tornado": {
        "headers": {"Server": r"TornadoServer(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },

    # --- Languages / Runtimes ---
    "PHP": {
        "headers": {"X-Powered-By": r"PHP(?:/(\d+[\d.]+))?"},
        "cookies": [r"PHPSESSID"],
        "category": "Language",
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r"(\d+[\d.]+)"},
        "cookies": [r"ASP\.NET_SessionId"],
        "category": "Language",
    },
    "Node.js": {
        "headers": {"X-Powered-By": r"Express"},
        "category": "Language",
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": r"Phusion Passenger(?:/(\d+[\d.]+))?"},
        "cookies": [r"_session_id"],
        "html": [r'content="Ruby on Rails'],
        "category": "Framework",
    },
    "Python": {
        "headers": {"X-Powered-By": r"Python(?:/(\d+[\d.]+))?"},
        "category": "Language",
    },

    # --- Frameworks ---
    "Laravel": {
        "cookies": [r"laravel_session", r"XSRF-TOKEN"],
        "html": [r'csrf-token.*laravel', r'Laravel'],
        "category": "Framework",
    },
    "CakePHP": {
        "html": [r'cakephp', r'CakePHP'],
        "category": "Framework",
    },
    "Yii": {
        "html": [r'Yii Framework', r'yiiframework'],
        "category": "Framework",
    },
    "Zend Framework": {
        "html": [r'Zend Framework', r'zf2'],
        "category": "Framework",
    },
    "FuelPHP": {
        "html": [r'FuelPHP', r'fuelphp'],
        "category": "Framework",
    },
    "Slim Framework": {
        "html": [r'Slim Framework', r'slim'],
        "category": "Framework",
    },
    "Hapi.js": {
        "html": [r'hapi', r'hapi.js'],
        "category": "Framework",
    },
    "Koa": {
        "html": [r'koa', r'Koa'],
        "category": "Framework",
    },
    "NestJS": {
        "html": [r'nestjs', r'@nestjs'],
        "category": "Framework",
    },
    "AdonisJS": {
        "html": [r'adonis', r'adonisjs'],
        "category": "Framework",
    },
    "Nuxt.js": {
        "html": [r'__NUXT__', r'/_nuxt/'],
        "category": "JS Framework",
    },
    "Svelte": {
        "html": [r'svelte-', r'__svelte'],
        "category": "JS Framework",
    },
    "Preact": {
        "html": [r'preact', r'preactjs'],
        "category": "JS Framework",
    },
    "Alpine.js": {
        "html": [r'alpinejs', r'x-data'],
        "category": "JS Framework",
    },
    "Mithril": {
        "html": [r'mithril', r'mithril.js'],
        "category": "JS Framework",
    },
    "Ember.js": {
        "html": [r'ember', r'ember.js'],
        "category": "JS Framework",
    },
    "Backbone.js": {
        "html": [r'backbone', r'backbone.js'],
        "category": "JS Framework",
    },
    "Knockout.js": {
        "html": [r'knockout', r'knockoutjs'],
        "category": "JS Framework",
    },
    "Aurelia": {
        "html": [r'aurelia', r'aurelia.io'],
        "category": "JS Framework",
    },
    "Dojo": {
        "html": [r'dojo', r'dojo.js'],
        "category": "JS Framework",
    },
    "Django": {
        "cookies": [r"csrftoken", r"sessionid"],
        "html": [r"csrfmiddlewaretoken"],
        "category": "Framework",
    },
    "Flask": {
        "cookies": [r"session"],
        "headers": {"Server": r"Werkzeug"},
        "category": "Framework",
    },
    "Express.js": {
        "headers": {"X-Powered-By": r"Express"},
        "category": "Framework",
    },
    "FastAPI": {
        "html": [r"fastapi", r"/openapi\.json", r"/docs"],
        "paths": [r"/openapi\.(?:json|yaml)", r"/docs(?:/.*)?", r"/redoc(?:/.*)?"],
        "category": "Framework",
    },
    "GraphQL": {
        "html": [r"graphql", r"__schema"],
        "paths": [r"/graphql(?:/.*)?", r"/graphiql(?:/.*)?", r"/graphql-ws(?:/.*)?"],
        "category": "API",
    },
    "Swagger UI": {
        "html": [r"swagger-ui", r"swagger"],
        "paths": [r"/swagger(?:-ui)?(?:/.*)?", r"/docs(?:/.*)?", r"/redoc(?:/.*)?"],
        "category": "API Docs",
    },
    "OpenAPI": {
        "html": [r"openapi", r"OpenAPI"],
        "paths": [r"/openapi\.(?:json|yaml)", r"/openapi(?:/.*)?"],
        "category": "API Docs",
    },
    "Spring": {
        "cookies": [r"JSESSIONID"],
        "headers": {"X-Application-Context": r".+"},
        "category": "Framework",
    },
    "Symfony": {
        "cookies": [r"PHPSESSID"],
        "html": [r"Symfony", r"sf_redirect"],
        "category": "Framework",
    },
    "CodeIgniter": {
        "cookies": [r"ci_session"],
        "html": [r"CodeIgniter"],
        "category": "Framework",
    },

    # --- CMS ---
    "WordPress": {
        "html": [r'/wp-content/', r'/wp-includes/', r'wordpress'],
        "meta": {"generator": r"WordPress(?:\s(\d+[\d.]+))?"},
        "category": "CMS",
    },
    "Elementor": {
        "html": [r'/wp-content/plugins/elementor/', r'elementor'],
        "category": "WordPress Plugin",
    },
    "WooCommerce": {
        "html": [r'/wp-content/plugins/woocommerce/', r'woocommerce'],
        "category": "WordPress Plugin",
    },
    "Yoast SEO": {
        "html": [r'/wp-content/plugins/wordpress-seo/', r'yoast'],
        "category": "WordPress Plugin",
    },
    "Contact Form 7": {
        "html": [r'/wp-content/plugins/contact-form-7/', r'contact-form-7'],
        "category": "WordPress Plugin",
    },
    "WPForms": {
        "html": [r'/wp-content/plugins/wpforms-lite/', r'wpforms'],
        "category": "WordPress Plugin",
    },
    "WP Rocket": {
        "html": [r'/wp-content/plugins/wp-rocket/', r'wp-rocket'],
        "category": "WordPress Plugin",
    },
    "LiteSpeed Cache": {
        "html": [r'/wp-content/plugins/litespeed-cache/', r'litespeed-cache'],
        "category": "WordPress Plugin",
    },
    "All in One SEO": {
        "html": [r'/wp-content/plugins/all-in-one-seo-pack/', r'aioseo'],
        "category": "WordPress Plugin",
    },
    "WPBakery": {
        "html": [r'/wp-content/plugins/js_composer/', r'wpbakery'],
        "category": "WordPress Plugin",
    },
    "Divi": {
        "html": [r'/wp-content/themes/divi/', r'divi'],
        "category": "WordPress Theme",
    },
    "Avada": {
        "html": [r'/wp-content/themes/avada/', r'avada'],
        "category": "WordPress Theme",
    },
    "GeneratePress": {
        "html": [r'/wp-content/themes/generatepress/', r'generatepress'],
        "category": "WordPress Theme",
    },
    "WP Super Cache": {
        "html": [r'/wp-content/plugins/wp-super-cache/', r'wpsupercache'],
        "category": "WordPress Plugin",
    },
    "WP Mail SMTP": {
        "html": [r'/wp-content/plugins/wp-mail-smtp/', r'wpmailsmtp'],
        "category": "WordPress Plugin",
    },
    "UpdraftPlus": {
        "html": [r'/wp-content/plugins/updraftplus/', r'updraftplus'],
        "category": "WordPress Plugin",
    },
    "Really Simple SSL": {
        "html": [r'/wp-content/plugins/really-simple-ssl/', r'really-simple-ssl'],
        "category": "WordPress Plugin",
    },
    "SiteOrigin": {
        "html": [r'/wp-content/plugins/siteorigin-panels/', r'siteorigin'],
        "category": "WordPress Plugin",
    },
    "BuddyPress": {
        "html": [r'/wp-content/plugins/buddypress/', r'buddypress'],
        "category": "WordPress Plugin",
    },
    "bbPress": {
        "html": [r'/wp-content/plugins/bbpress/', r'bbpress'],
        "category": "WordPress Plugin",
    },
    "The Events Calendar": {
        "html": [r'/wp-content/plugins/the-events-calendar/', r'the-events-calendar'],
        "category": "WordPress Plugin",
    },
    "Advanced Custom Fields": {
        "html": [r'/wp-content/plugins/advanced-custom-fields/', r'acf'],
        "category": "WordPress Plugin",
    },
    "ACF Pro": {
        "html": [r'/wp-content/plugins/advanced-custom-fields-pro/', r'acf-pro'],
        "category": "WordPress Plugin",
    },
    "Jetpack": {
        "html": [r'/wp-content/plugins/jetpack/', r'jetpack'],
        "category": "WordPress Plugin",
    },
    "Astra": {
        "html": [r'/wp-content/themes/astra/', r'astra'],
        "category": "WordPress Theme",
    },
    "OceanWP": {
        "html": [r'/wp-content/themes/oceanwp/', r'oceanwp'],
        "category": "WordPress Theme",
    },
    "Kadence": {
        "html": [r'/wp-content/themes/kadence/', r'kadence'],
        "category": "WordPress Theme",
    },
    "WP Fastest Cache": {
        "html": [r'/wp-content/plugins/wp-fastest-cache/', r'wpfastestcache'],
        "category": "WordPress Plugin",
    },
    "Perfmatters": {
        "html": [r'/wp-content/plugins/perfmatters/', r'perfmatters'],
        "category": "WordPress Plugin",
    },
    "WP Reset": {
        "html": [r'/wp-content/plugins/wp-reset/', r'wp-reset'],
        "category": "WordPress Plugin",
    },
    "WP Cerber": {
        "html": [r'/wp-content/plugins/wp-cerber/', r'wp-cerber'],
        "category": "WordPress Plugin",
    },
    "Sucuri Security": {
        "html": [r'/wp-content/plugins/sucuri-scanner/', r'sucuri'],
        "category": "WordPress Plugin",
    },
    "Wordfence": {
        "html": [r'/wp-content/plugins/wordfence/', r'wordfence'],
        "category": "WordPress Plugin",
    },
    "Solid Security": {
        "html": [r'/wp-content/plugins/solid-security/', r'solidsecurity'],
        "category": "WordPress Plugin",
    },
    "WP Content Copy Protection": {
        "html": [r'/wp-content/plugins/wp-content-copy-protection/', r'wp-content-copy-protection'],
        "category": "WordPress Plugin",
    },
    "WP Optimize": {
        "html": [r'/wp-content/plugins/wp-optimize/', r'wp-optimize'],
        "category": "WordPress Plugin",
    },
    "Broken Link Checker": {
        "html": [r'/wp-content/plugins/broken-link-checker/', r'broken-link-checker'],
        "category": "WordPress Plugin",
    },
    "WPForms Lite": {
        "html": [r'/wp-content/plugins/wpforms-lite/', r'wpforms'],
        "category": "WordPress Plugin",
    },
    "FluentForms": {
        "html": [r'/wp-content/plugins/fluentform/', r'fluentform'],
        "category": "WordPress Plugin",
    },
    "Forminator": {
        "html": [r'/wp-content/plugins/forminator/', r'forminator'],
        "category": "WordPress Plugin",
    },
    "Ninja Forms": {
        "html": [r'/wp-content/plugins/ninja-forms/', r'ninja-forms'],
        "category": "WordPress Plugin",
    },
    "MailPoet": {
        "html": [r'/wp-content/plugins/mailpoet/', r'mailpoet'],
        "category": "WordPress Plugin",
    },
    "MemberPress": {
        "html": [r'/wp-content/plugins/memberpress/', r'memberpress'],
        "category": "WordPress Plugin",
    },
    "LearnDash": {
        "html": [r'/wp-content/plugins/learndash/', r'learndash'],
        "category": "WordPress Plugin",
    },
    "Tutor LMS": {
        "html": [r'/wp-content/plugins/tutor-lms/', r'tutor-lms'],
        "category": "WordPress Plugin",
    },
    "Restrict Content Pro": {
        "html": [r'/wp-content/plugins/restrict-content-pro/', r'restrict-content-pro'],
        "category": "WordPress Plugin",
    },
    "WooCommerce Subscriptions": {
        "html": [r'/wp-content/plugins/woocommerce-subscriptions/', r'woocommerce-subscriptions'],
        "category": "WordPress Plugin",
    },
    "WooCommerce Memberships": {
        "html": [r'/wp-content/plugins/woocommerce-memberships/', r'woocommerce-memberships'],
        "category": "WordPress Plugin",
    },
    "YITH WooCommerce Wishlist": {
        "html": [r'/wp-content/plugins/yith-woocommerce-wishlist/', r'yith-woocommerce-wishlist'],
        "category": "WordPress Plugin",
    },
    "WooCommerce Bookings": {
        "html": [r'/wp-content/plugins/woocommerce-bookings/', r'woocommerce-bookings'],
        "category": "WordPress Plugin",
    },
    "Slider Revolution": {
        "html": [r'/wp-content/plugins/revslider/', r'revslider'],
        "category": "WordPress Plugin",
    },
    "LayerSlider": {
        "html": [r'/wp-content/plugins/layerslider/', r'layerslider'],
        "category": "WordPress Plugin",
    },
    "Envira Gallery": {
        "html": [r'/wp-content/plugins/envira-gallery-lite/', r'envira-gallery'],
        "category": "WordPress Plugin",
    },
    "NextGEN Gallery": {
        "html": [r'/wp-content/plugins/nextgen-gallery/', r'nextgen-gallery'],
        "category": "WordPress Plugin",
    },
    "MetaSlider": {
        "html": [r'/wp-content/plugins/ml-slider/', r'meta-slider'],
        "category": "WordPress Plugin",
    },
    "WP Job Manager": {
        "html": [r'/wp-content/plugins/wp-job-manager/', r'wp-job-manager'],
        "category": "WordPress Plugin",
    },
    "GeoDirectory": {
        "html": [r'/wp-content/plugins/geodirectory/', r'geodirectory'],
        "category": "WordPress Plugin",
    },
    "Drupal": {
        "headers": {"X-Generator": r"Drupal(?:\s(\d+))?"},
        "html": [r'/sites/default/files/', r'Drupal\.settings'],
        "meta": {"generator": r"Drupal(?:\s(\d+[\d.]+))?"},
        "category": "CMS",
    },
    "Joomla": {
        "html": [r'/media/jui/', r'/components/com_'],
        "meta": {"generator": r"Joomla!(?:\s(\d+[\d.]+))?"},
        "category": "CMS",
    },
    "Magento": {
        "cookies": [r"frontend"],
        "html": [r'Mage\.', r'/skin/frontend/', r'var BLANK_URL'],
        "category": "CMS / E-Commerce",
    },
    "Shopify": {
        "html": [r'cdn\.shopify\.com', r'Shopify\.theme'],
        "category": "CMS / E-Commerce",
    },
    "BigCommerce": {
        "html": [r'bigcommerce', r'cdn\.bigcommerce'],
        "category": "CMS / E-Commerce",
    },
    "PrestaShop": {
        "html": [r'prestashop', r'PrestaShop'],
        "category": "CMS / E-Commerce",
    },
    "OpenCart": {
        "html": [r'opencart', r'OpenCart'],
        "category": "CMS / E-Commerce",
    },
    "osCommerce": {
        "html": [r'oscommerce', r'osCommerce'],
        "category": "CMS / E-Commerce",
    },
    "Zen Cart": {
        "html": [r'zencart', r'Zen Cart'],
        "category": "CMS / E-Commerce",
    },
    "X-Cart": {
        "html": [r'x-cart', r'X-Cart'],
        "category": "CMS / E-Commerce",
    },
    "Miva Merchant": {
        "html": [r'miva', r'Miva'],
        "category": "CMS / E-Commerce",
    },
    "CS-Cart": {
        "html": [r'cs-cart', r'CS-Cart'],
        "category": "CMS / E-Commerce",
    },
    "Ghost": {
        "meta": {"generator": r"Ghost(?:\s(\d+[\d.]+))?"},
        "html": [r'ghost\.org', r'content="Ghost'],
        "category": "CMS",
    },
    "Concrete CMS": {
        "html": [r'concrete5', r'concrete-cms'],
        "category": "CMS",
    },
    "Grav": {
        "html": [r'grav', r'gravatar'],
        "category": "CMS",
    },
    "ProcessWire": {
        "html": [r'processwire', r'ProcessWire'],
        "category": "CMS",
    },
    "Bolt CMS": {
        "html": [r'bolt.cm', r'bolt'],
        "category": "CMS",
    },
    "Pimcore": {
        "html": [r'pimcore', r'Pimcore'],
        "category": "CMS",
    },
    "Sitecore": {
        "html": [r'sitecore', r'Sitecore'],
        "category": "CMS",
    },
    "Kentico": {
        "html": [r'kentico', r'Kentico'],
        "category": "CMS",
    },
    "Umbraco": {
        "html": [r'umbraco', r'Umbraco'],
        "category": "CMS",
    },
    "Typo3": {
        "html": [r'typo3', r'TYPO3'],
        "category": "CMS",
    },
    "MODX": {
        "html": [r'modx', r'MODX'],
        "category": "CMS",
    },
    "SilverStripe": {
        "html": [r'silverstripe', r'SilverStripe'],
        "category": "CMS",
    },
    "Wix": {
        "html": [r'wixsite\.com', r'static\.wixstatic\.com'],
        "category": "Site Builder",
    },
    "Squarespace": {
        "html": [r'squarespace\.com', r'static1\.squarespace\.com'],
        "category": "Site Builder",
    },
    "Webflow": {
        "html": [r'webflow\.com', r'data-wf-'],
        "category": "Site Builder",
    },

    # --- JS Frameworks ---
    "React": {
        "html": [r'__reactFiber', r'__reactProps', r'react\.development\.js', r'react\.production\.min\.js', r'_reactRootContainer'],
        "scripts": [r'react(?:\.min)?\.js', r'react-dom'],
        "category": "JS Framework",
    },
    "Vue.js": {
        "html": [r'__vue__', r'data-v-', r'vue\.min\.js', r'vue\.js'],
        "scripts": [r'vue(?:\.min)?\.js'],
        "category": "JS Framework",
    },
    "Angular": {
        "html": [r'ng-version=', r'ng-app', r'angular\.min\.js'],
        "scripts": [r'angular(?:\.min)?\.js'],
        "category": "JS Framework",
    },
    "Next.js": {
        "html": [r'__NEXT_DATA__', r'/_next/static/'],
        "headers": {"X-Powered-By": r"Next\.js"},
        "category": "JS Framework",
    },
    "Nuxt.js": {
        "html": [r'__NUXT__', r'/_nuxt/'],
        "category": "JS Framework",
    },
    "Svelte": {
        "html": [r'svelte-', r'__svelte'],
        "category": "JS Framework",
    },
    "jQuery": {
        "html": [r'jquery(?:\.min)?\.js', r'jQuery v(\d+[\d.]+)'],
        "scripts": [r'jquery(?:-(\d+[\d.]+))?(?:\.min)?\.js'],
        "category": "JS Library",
    },
    "Lodash": {
        "html": [r'lodash', r'lodash\.min\.js'],
        "category": "JS Library",
    },
    "Underscore.js": {
        "html": [r'underscore', r'underscore\.min\.js'],
        "category": "JS Library",
    },
    "Moment.js": {
        "html": [r'moment', r'moment\.min\.js'],
        "category": "JS Library",
    },
    "D3.js": {
        "html": [r'd3\.js', r'd3\.min\.js'],
        "category": "JS Library",
    },
    "Three.js": {
        "html": [r'three\.js', r'three\.min\.js'],
        "category": "JS Library",
    },
    "Chart.js": {
        "html": [r'chart\.js', r'chart\.min\.js'],
        "category": "JS Library",
    },
    "Highcharts": {
        "html": [r'highcharts', r'highcharts\.js'],
        "category": "JS Library",
    },
    "Select2": {
        "html": [r'select2', r'select2\.js'],
        "category": "JS Library",
    },
    "Axios": {
        "html": [r'axios', r'axios\.min\.js'],
        "category": "JS Library",
    },
    "Bootstrap": {
        "html": [r'bootstrap(?:\.min)?\.css', r'bootstrap(?:\.min)?\.js'],
        "scripts": [r'bootstrap(?:-(\d+[\d.]+))?'],
        "category": "CSS Framework",
    },
    "Tailwind CSS": {
        "html": [r'tailwindcss', r'class="[^"]*(?:flex|grid|text-\w+|bg-\w+|p-\d|m-\d)[^"]*"'],
        "category": "CSS Framework",
    },
    "Bulma": {
        "html": [r'bulma', r'bulma\.css'],
        "category": "CSS Framework",
    },
    "Foundation": {
        "html": [r'foundation', r'foundation\.min\.css'],
        "category": "CSS Framework",
    },
    "Materialize": {
        "html": [r'materialize', r'materialize\.css'],
        "category": "CSS Framework",
    },
    "UIKit": {
        "html": [r'uikit', r'uikit\.css'],
        "category": "CSS Framework",
    },
    "Semantic UI": {
        "html": [r'semantic-ui', r'semantic\.min\.css'],
        "category": "CSS Framework",
    },
    "MUI": {
        "html": [r'@mui', r'mui\.js'],
        "category": "UI Library",
    },
    "Gatsby": {
        "html": [r'gatsby', r'gatsby-image'],
        "category": "JS Framework",
    },
    "Remix": {
        "html": [r'remix', r'@remix-run'],
        "category": "JS Framework",
    },
    "Astro": {
        "html": [r'astro', r'@astrojs'],
        "category": "JS Framework",
    },
    "Vite": {
        "html": [r'vite', r'@vitejs'],
        "category": "Build Tool",
    },
    "Webpack": {
        "html": [r'webpack', r'webpack.js'],
        "category": "Build Tool",
    },
    "Parcel": {
        "html": [r'parcel', r'parcel-bundler'],
        "category": "Build Tool",
    },
    "Rollup": {
        "html": [r'rollup', r'rollupjs'],
        "category": "Build Tool",
    },

    # --- CDN / Cloud ---
    "Cloudflare": {
        "headers": {"CF-Ray": r".+", "Server": r"cloudflare"},
        "category": "CDN / Security",
    },
    "Cloudflare Turnstile": {
        "html": [r'turnstile', r'cf-turnstile'],
        "category": "Security",
    },
    "Fastly": {
        "headers": {"Fastly-Debug-Digest": r".+", "X-Served-By": r"cache-"},
        "category": "CDN",
    },
    "Akamai": {
        "headers": {"X-Akamai-Transformed": r".+", "X-Check-Cacheable": r".+"},
        "category": "CDN",
    },
    "BunnyCDN": {
        "html": [r'bunnycdn', r'b-cdn.net'],
        "category": "CDN",
    },
    "jsDelivr": {
        "html": [r'jsdelivr', r'cdn.jsdelivr.net'],
        "category": "CDN",
    },
    "unpkg": {
        "html": [r'unpkg', r'unpkg.com'],
        "category": "CDN",
    },
    "cdnjs": {
        "html": [r'cdnjs', r'cdnjs.cloudflare.com'],
        "category": "CDN",
    },
    "AWS": {
        "headers": {"x-amz-request-id": r".+", "x-amz-id-2": r".+"},
        "html": [r'amazonaws\.com', r'awsstatic'],
        "category": "Cloud",
    },
    "Google Cloud": {
        "html": [r'cloud\.google\.com', r'storage\.googleapis\.com'],
        "category": "Cloud",
    },
    "Heroku": {
        "html": [r'herokuapp\.com', r'heroku'],
        "category": "Cloud",
    },
    "DigitalOcean": {
        "html": [r'digitalocean', r'digitaloceanspaces\.com'],
        "category": "Cloud",
    },
    "Vercel": {
        "html": [r'vercel\.app', r'_next', r'vercel'],
        "category": "Cloud",
    },
    "Cloudflare Pages": {
        "headers": {"Server": r"cloudflare"},
        "html": [r'cloudflarepages', r'pages.dev'],
        "category": "Hosting",
    },
    "BunnyCDN": {
        "html": [r'bunnycdn', r'b-cdn.net'],
        "category": "CDN",
    },
    "jsDelivr": {
        "html": [r'cdn.jsdelivr.net', r'jsdelivr'],
        "category": "CDN",
    },
    "unpkg": {
        "html": [r'unpkg.com', r'unpkg'],
        "category": "CDN",
    },
    "cdnjs": {
        "html": [r'cdnjs.cloudflare.com', r'cdnjs'],
        "category": "CDN",
    },
    "Sentry": {
        "html": [r'sentry', r'sentry.io'],
        "scripts": [r'sentry'],
        "category": "Error Tracking",
    },
    "Rollbar": {
        "html": [r'rollbar', r'rollbar.com'],
        "category": "Error Tracking",
    },
    "Bugsnag": {
        "html": [r'bugsnag', r'bugsnag.com'],
        "category": "Error Tracking",
    },
    "LogRocket": {
        "html": [r'logrocket', r'logrocket.com'],
        "category": "Error Tracking",
    },
    "New Relic": {
        "html": [r'newrelic', r'newrelic.com'],
        "category": "Monitoring",
    },
    "Datadog": {
        "html": [r'datadoghq', r'datadog'],
        "category": "Monitoring",
    },
    "AWS CloudFront": {
        "headers": {"X-Amz-Cf-Id": r".+", "Via": r"CloudFront"},
        "category": "CDN",
    },
    "Fastly": {
        "headers": {"X-Served-By": r"cache-", "Fastly-Debug-Digest": r".+"},
        "category": "CDN",
    },
    "Akamai": {
        "headers": {"X-Check-Cacheable": r".+", "X-Akamai-Transformed": r".+"},
        "category": "CDN",
    },
    "Varnish": {
        "headers": {"X-Varnish": r".+", "Via": r"varnish"},
        "category": "Cache",
    },

    # --- WAF ---
    "AWS WAF": {
        "headers": {"X-AMZ-WAF": r".+"},
        "category": "WAF",
    },
    "Sucuri": {
        "headers": {"X-Sucuri-ID": r".+", "Server": r"Sucuri"},
        "category": "WAF",
    },
    "Imperva": {
        "headers": {"X-Iinfo": r".+"},
        "category": "WAF",
    },
    "ModSecurity": {
        "headers": {"X-Mod-Security": r".+"},
        "category": "WAF",
    },

    # --- Analytics ---
    "Google Analytics": {
        "html": [r'google-analytics\.com/analytics\.js', r'gtag\(', r'UA-\d+-\d+', r'G-[A-Z0-9]+'],
        "scripts": [r'google-analytics\.com', r'googletagmanager\.com'],
        "category": "Analytics",
    },
    "Google Tag Manager": {
        "html": [r'googletagmanager\.com/gtm\.js', r'GTM-[A-Z0-9]+'],
        "scripts": [r'googletagmanager\.com'],
        "category": "Analytics",
    },
    "Meta Pixel": {
        "html": [r'fbq\(', r'facebook\.com/tr'],
        "scripts": [r'connect\.facebook\.net'],
        "category": "Marketing",
    },
    "TikTok Pixel": {
        "html": [r'ttq\.track', r'tiktok\.com'],
        "scripts": [r'analytics\.tiktok\.com'],
        "category": "Marketing",
    },
    "HubSpot": {
        "html": [r'hs-scripts\.com', r'hubspot'],
        "scripts": [r'hs-scripts\.com'],
        "category": "Marketing",
    },
    "Mailchimp": {
        "html": [r'mailchimp', r'mc-embed'],
        "category": "Marketing",
    },
    "Pardot": {
        "html": [r'pardot', r'piwik\.tracking'],
        "category": "Marketing",
    },
    "Customer.io": {
        "html": [r'customer\.io', r'customerio'],
        "category": "Marketing",
    },
    "Google Tag Manager": {
        "html": [r'googletagmanager\.com/gtm\.js', r'GTM-[A-Z0-9]+'],
        "scripts": [r'googletagmanager\.com'],
        "category": "Analytics",
    },
    "Meta Pixel": {
        "html": [r'fbq\(', r'facebook\.com/tr'],
        "scripts": [r'connect\.facebook\.net'],
        "category": "Marketing",
    },
    "TikTok Pixel": {
        "html": [r'ttq\.track', r'tiktok\.com'],
        "scripts": [r'analytics\.tiktok\.com'],
        "category": "Marketing",
    },
    "Hotjar": {
        "html": [r'hotjar\.com', r'hjid:', r'hjsv:'],
        "scripts": [r'hotjar\.com'],
        "category": "Analytics",
    },
    "Mixpanel": {
        "html": [r'mixpanel', r'mixpanel\.com'],
        "category": "Analytics",
    },
    "Segment": {
        "html": [r'segment\.com', r'analytics\.js'],
        "category": "Analytics",
    },
    "HubSpot": {
        "html": [r'hs-scripts\.com', r'hubspot'],
        "scripts": [r'hs-scripts\.com'],
        "category": "Marketing",
    },
    "Mailchimp": {
        "html": [r'mailchimp', r'mc-embed'],
        "category": "Marketing",
    },
    "Pardot": {
        "html": [r'piwik\.tracking', r'pardot'],
        "category": "Marketing",
    },
    "Customer.io": {
        "html": [r'customer\.io', r'customerio'],
        "category": "Marketing",
    },
    "Adobe Analytics": {
        "html": [r's_code\.js', r'satelliteLib', r'AppMeasurement'],
        "category": "Analytics",
    },
    "Mixpanel": {
        "html": [r'mixpanel', r'mixpanel.com'],
        "category": "Analytics",
    },
    "Amplitude": {
        "html": [r'amplitude', r'amplitude\.com'],
        "category": "Analytics",
    },
    "Heap": {
        "html": [r'heap\.io', r'heap-'],
        "category": "Analytics",
    },
    "Segment": {
        "html": [r'segment\.com', r'analytics\.js'],
        "category": "Analytics",
    },
    "Crazy Egg": {
        "html": [r'crazyegg', r'ce\.js'],
        "category": "Analytics",
    },
    "Hotjar": {
        "html": [r'hotjar\.com', r'hjid:', r'hjsv:'],
        "category": "Analytics",
    },
    "Google Tag Manager": {
        "html": [r'googletagmanager\.com/gtm\.js', r'GTM-[A-Z0-9]+'],
        "category": "Analytics",
    },
    "Hotjar": {
        "html": [r'hotjar\.com', r'hjid:', r'hjsv:'],
        "category": "Analytics",
    },
    "Matomo": {
        "html": [r'matomo\.js', r'piwik\.js', r'_paq\.push'],
        "category": "Analytics",
    },
    "Plausible": {
        "html": [r'plausible\.io/js'],
        "category": "Analytics",
    },

    # --- Security Headers ---
    "HSTS": {
        "headers": {"Strict-Transport-Security": r".+"},
        "category": "Security Header",
    },
    "CSP": {
        "headers": {"Content-Security-Policy": r".+"},
        "category": "Security Header",
    },
    "X-Frame-Options": {
        "headers": {"X-Frame-Options": r".+"},
        "category": "Security Header",
    },
    "X-XSS-Protection": {
        "headers": {"X-XSS-Protection": r".+"},
        "category": "Security Header",
    },

    # --- Databases / Backend hints ---
    "MySQL": {
        "html": [r'mysql_connect', r'MySQL'],
        "category": "Database",
    },
    "MongoDB": {
        "html": [r'mongodb', r'MongoClient'],
        "category": "Database",
    },
    "Elasticsearch": {
        "html": [r'elasticsearch', r'elastic\.co'],
        "category": "Search Engine",
    },

    # --- Hosting ---
    "Vercel": {
        "headers": {"X-Vercel-Id": r".+", "Server": r"Vercel"},
        "category": "Hosting",
    },
    "AWS": {
        "headers": {"x-amz-request-id": r".+", "x-amz-id-2": r".+"},
        "html": [r'amazonaws\.com', r'awsstatic'],
        "category": "Cloud",
    },
    "Google Cloud": {
        "html": [r'cloud\.google\.com', r'storage\.googleapis\.com'],
        "category": "Cloud",
    },
    "Heroku": {
        "headers": {"Via": r"1\.1 vegur"},
        "html": [r'herokuapp\.com', r'heroku'],
        "category": "Cloud",
    },
    "DigitalOcean": {
        "html": [r'digitalocean', r'digitaloceanspaces\.com'],
        "category": "Cloud",
    },
    "Netlify": {
        "headers": {"X-Nf-Request-Id": r".+", "Server": r"Netlify"},
        "category": "Hosting",
    },
    "Netlify": {
        "headers": {"X-Nf-Request-Id": r".+", "Server": r"Netlify"},
        "category": "Hosting",
    },
    "Heroku": {
        "headers": {"Via": r"1\.1 vegur"},
        "category": "Hosting",
    },
    "GitHub Pages": {
        "html": [r'github\.io'],
        "category": "Hosting",
    },

    # --- Payment ---
    "Stripe": {
        "html": [r'js\.stripe\.com', r'Stripe\('],
        "scripts": [r'js\.stripe\.com'],
        "category": "Payment",
    },
    "PayPal": {
        "html": [r'paypal\.com/sdk', r'paypalobjects\.com'],
        "category": "Payment",
    },
    "Klarna": {
        "html": [r'klarna', r'klarna\.com'],
        "category": "Payment",
    },
    "Apple Pay": {
        "html": [r'apple-pay', r'paymentrequest'],
        "category": "Payment",
    },
    "Shopify": {
        "html": [r'cdn\.shopify\.com', r'shopify', r'Shopify\.theme'],
        "scripts": [r'cdn\.shopify\.com'],
        "category": "E-Commerce",
    },
    "ReCharge": {
        "html": [r'recharge', r'rechargeapps\.com'],
        "category": "E-Commerce",
    },
    "Bold Commerce": {
        "html": [r'bold\.commerce', r'boldapps'],
        "category": "E-Commerce",
    },
    "Skio": {
        "html": [r'skio', r'skiopages'],
        "category": "E-Commerce",
    },
    "ShipStation": {
        "html": [r'shipstation', r'shipstation\.com'],
        "category": "Fulfillment",
    },
    "ShipBob": {
        "html": [r'shipbob', r'shipbob\.com'],
        "category": "Fulfillment",
    },
    "Easyship": {
        "html": [r'easyship', r'easyship\.com'],
        "category": "Fulfillment",
    },
    "Zendesk": {
        "html": [r'zendesk', r'zendesk\.com'],
        "category": "CRM",
    },
    "Intercom": {
        "html": [r'intercom', r'intercom\.io'],
        "category": "CRM",
    },
    "Salesforce": {
        "html": [r'salesforce', r'force\.com'],
        "category": "CRM",
    },
    "Pipedrive": {
        "html": [r'pipedrive', r'pipedrive\.com'],
        "category": "CRM",
    },
    "Drift": {
        "html": [r'drift', r'drift\.com'],
        "category": "CRM",
    },
    "Calendly": {
        "html": [r'calendly', r'calendly\.com'],
        "category": "Scheduling",
    },
    "Typeform": {
        "html": [r'typeform', r'typeform\.com'],
        "category": "Forms",
    },
    "Jotform": {
        "html": [r'jotform', r'jotform\.com'],
        "category": "Forms",
    },
    "Magento": {
        "html": [r'Mage\.', r'/skin/frontend/', r'var BLANK_URL'],
        "cookies": [r'frontend'],
        "category": "E-Commerce",
    },
    "BigCommerce": {
        "html": [r'bigcommerce', r'cdn\.bigcommerce'],
        "category": "E-Commerce",
    },
    "PrestaShop": {
        "html": [r'prestashop', r'PrestaShop'],
        "category": "E-Commerce",
    },
    "OpenCart": {
        "html": [r'opencart', r'OpenCart'],
        "category": "E-Commerce",
    },
    "PayPal": {
        "html": [r'paypal\.com/sdk', r'paypalobjects\.com'],
        "category": "Payment",
    },
    "Braintree": {
        "html": [r'braintreegateway\.com', r'paypal\.com/sdk'],
        "category": "Payment",
    },
    "Authorize.Net": {
        "html": [r'authorize\.net', r'accept\.js'],
        "category": "Payment",
    },
    "Square": {
        "html": [r'squareup\.com', r'sqpaymentform'],
        "category": "Payment",
    },
    "Adyen": {
        "html": [r'adyen\.com', r'adyen'],
        "category": "Payment",
    },
    "Checkout.com": {
        "html": [r'checkout\.com', r'cko'],
        "category": "Payment",
    },
    "Paddle": {
        "html": [r'paddle\.com', r'paddle'],
        "category": "Payment",
    },

    # --- Misc ---
    "Font Awesome": {
        "html": [r'font-awesome', r'fontawesome'],
        "scripts": [r'fontawesome'],
        "category": "UI Library",
    },
    "reCAPTCHA": {
        "html": [r'google\.com/recaptcha', r'grecaptcha'],
        "category": "Security",
    },
    "Intercom": {
        "html": [r'intercom\.io', r'intercomSettings'],
        "category": "CRM / Chat",
    },
    "Zendesk": {
        "html": [r'zendesk\.com', r'zE\('],
        "category": "CRM / Chat",
    },

    # --- Infrastructure, Admin, and DevOps services ---
    "Tomcat": {
        "headers": {"Server": r"Tomcat(?:/(\d+[\d.]+))?", "X-Powered-By": r"Tomcat"},
        "cookies": [r"JSESSIONID"],
        "html": [r'/manager/html', r'tomcat', r'/docs/config'],
        "paths": [r'/manager/html', r'/host-manager/html', r'/docs'],
        "category": "Web Server",
    },
    "Jenkins": {
        "headers": {"X-Jenkins": r".+", "Server": r"Jenkins"},
        "html": [r'Jenkins', r'jenkins-ci\.org', r'/static/jenkins'],
        "paths": [r'/login', r'/script', r'/manage'],
        "category": "CI / CD",
    },
    "Nifi": {
        "headers": {"Server": r"NiFi"},
        "html": [r'NiFi', r'/nifi/', r'nifi-api'],
        "paths": [r'/nifi', r'/nifi/login', r'/nifi-api'],
        "category": "Data Platform",
    },
    "Grafana": {
        "headers": {"Server": r"Grafana"},
        "html": [r'Grafana', r'grafana-static', r'/login'],
        "category": "Monitoring",
    },
    "Kibana": {
        "html": [r'Kibana', r'app/kibana', r'kibana'],
        "category": "Monitoring",
    },
    "Prometheus": {
        "html": [r'Prometheus', r'/graph', r'/api/v1/targets'],
        "category": "Monitoring",
    },
    "OpenSSH": {
        "headers": {"Server": r"OpenSSH(?:/(\d+[\d.]+))?"},
        "category": "Remote Access",
    },
    "RabbitMQ": {
        "headers": {"Server": r"RabbitMQ"},
        "html": [r'RabbitMQ', r'/api/health'],
        "category": "Messaging",
    },
    "Redis": {
        "headers": {"Server": r"Redis"},
        "html": [r'redis_version', r'Redis', r'/info'],
        "category": "Database",
    },
    "PostgreSQL": {
        "html": [r'PostgreSQL', r'pgAdmin', r'/pgadmin'],
        "category": "Database",
    },
    "pgAdmin": {
        "html": [r'pgAdmin', r'pgadmin'],
        "category": "Database Admin",
    },
    "Apache Solr": {
        "html": [r'Apache Solr', r'/solr/', r'solr'],
        "category": "Search Engine",
    },
    "OpenSearch": {
        "html": [r'OpenSearch', r'opensearch'],
        "category": "Search Engine",
    },
    "Zookeeper": {
        "html": [r'Zookeeper', r'zk', r'zookeeper'],
        "category": "Distributed Systems",
    },
    "Kafka": {
        "html": [r'Kafka', r'kafka-ui', r'kafkaconsumer'],
        "category": "Messaging",
    },
    "ActiveMQ": {
        "html": [r'ActiveMQ', r'activemq'],
        "category": "Messaging",
    },
    "Consul": {
        "html": [r'Consul', r'consul'],
        "category": "Service Discovery",
    },
    "Vault": {
        "html": [r'Vault', r'vault'],
        "category": "Secrets Management",
    },
    "Harbor": {
        "html": [r'Harbor', r'harbor-registry', r'harbor'],
        "category": "Container Registry",
    },
    "GitLab": {
        "html": [r'GitLab', r'gitlab-ce', r'gitlab'],
        "paths": [r'/users/sign_in', r'/explore', r'/profile'],
        "category": "DevOps",
    },
    "Gitea": {
        "html": [r'Gitea', r'gitea'],
        "category": "DevOps",
    },
    "Jira": {
        "html": [r'Jira', r'atlassian\.net', r'jira'],
        "category": "Project Management",
    },
    "Confluence": {
        "html": [r'Confluence', r'confluence', r'atlassian'],
        "category": "Project Management",
    },
    "SonarQube": {
        "html": [r'SonarQube', r'sonarqube', r'sonar'],
        "category": "Code Quality",
    },
    "TeamCity": {
        "html": [r'TeamCity', r'teamcity'],
        "category": "CI / CD",
    },
    "Bitbucket": {
        "html": [r'Bitbucket', r'bitbucket'],
        "category": "DevOps",
    },
    "Rancher": {
        "html": [r'Rancher', r'rancher'],
        "category": "Container Orchestration",
    },
    "Portainer": {
        "html": [r'Portainer', r'portainer'],
        "category": "Container Management",
    },
    "Mattermost": {
        "html": [r'Mattermost', r'mattermost'],
        "category": "Collaboration",
    },
    "OpenVPN": {
        "headers": {"Server": r"OpenVPN"},
        "html": [r'OpenVPN', r'openvpn'],
        "paths": [r'/admin', r'/openvpn'],
        "category": "Remote Access",
    },
    "pfSense": {
        "html": [r'pfSense', r'pfsense'],
        "category": "Firewall / Network",
    },
    "Nagios": {
        "html": [r'Nagios', r'nagios'],
        "category": "Monitoring",
    },
    "Zabbix": {
        "html": [r'Zabbix', r'zabbix'],
        "category": "Monitoring",
    },
    "Cacti": {
        "html": [r'Cacti', r'cacti'],
        "category": "Monitoring",
    },
    "Splunk": {
        "html": [r'Splunk', r'splunkd'],
        "category": "Monitoring",
    },
    "Graylog": {
        "html": [r'Graylog', r'graylog'],
        "category": "Monitoring",
    },
    "Keycloak": {
        "html": [r'Keycloak', r'keycloak'],
        "category": "Identity",
    },
    "Apache Guacamole": {
        "html": [r'Guacamole', r'guacamole'],
        "paths": [r'/guacamole', r'/guacamole/login'],
        "category": "Remote Access",
    },
    "NetBox": {
        "html": [r'NetBox', r'netbox'],
        "category": "Infrastructure",
    },
    "LibreNMS": {
        "html": [r'LibreNMS', r'librenms'],
        "category": "Monitoring",
    },
    "Apache Superset": {
        "html": [r'Superset', r'superset'],
        "category": "Analytics",
    },
    "Metabase": {
        "html": [r'Metabase', r'metabase'],
        "category": "Analytics",
    },
    "Airflow": {
        "html": [r'Airflow', r'airflow'],
        "category": "Data Platform",
    },
    "Plesk": {
        "html": [r'Plesk', r'plesk'],
        "paths": [r'/smb/web/plesk', r'/login_up.php'],
        "category": "Hosting",
    },
    "cPanel": {
        "html": [r'cPanel', r'cpanel'],
        "paths": [r'/cpanel', r'/whm'],
        "category": "Hosting",
    },
    "DirectAdmin": {
        "html": [r'DirectAdmin', r'directadmin'],
        "paths": [r'/CMD_LOGIN', r'/CMD_HTTPD_CONF'],
        "category": "Hosting",
    },
    "Webmin": {
        "html": [r'Webmin', r'webmin'],
        "paths": [r'/webmin', r'/session_login.cgi'],
        "category": "Admin Panel",
    },
    "phpMyAdmin": {
        "html": [r'phpMyAdmin', r'phpmyadmin'],
        "paths": [r'/phpmyadmin', r'/phpMyAdmin', r'/pma', r'/sql'],
        "category": "Admin Panel",
    },
    "Adminer": {
        "html": [r'Adminer', r'adminer'],
        "paths": [r'/adminer', r'/adminer.php'],
        "category": "Admin Panel",
    },
    "pgAdmin": {
        "html": [r'pgAdmin', r'pgadmin'],
        "paths": [r'/pgadmin4', r'/pgadmin'],
        "category": "Admin Panel",
    },
    "RedisInsight": {
        "html": [r'RedisInsight', r'redisinsight'],
        "paths": [r'/redisinsight', r'/redis'],
        "category": "Admin Panel",
    },
    "Mongo Express": {
        "html": [r'Mongo Express', r'mongo-express'],
        "paths": [r'/mongo-express', r'/mongo'],
        "category": "Admin Panel",
    },
    "RabbitMQ Management": {
        "html": [r'RabbitMQ Management', r'rabbitmq'],
        "paths": [r'/rabbitmq', r'/rabbitmq/#/login'],
        "category": "Admin Panel",
    },
    "Kafka Manager": {
        "html": [r'Kafka Manager', r'kafka-manager'],
        "paths": [r'/kafka-manager', r'/manager/html'],
        "category": "Admin Panel",
    },
    "ActiveMQ Console": {
        "html": [r'ActiveMQ Console', r'activemq'],
        "paths": [r'/admin', r'/console'],
        "category": "Admin Panel",
    },
    "Nifi UI": {
        "html": [r'Nifi UI', r'nifi'],
        "paths": [r'/nifi', r'/nifi/login'],
        "category": "Admin Panel",
    },
    "Jupyter Notebook": {
        "html": [r'Jupyter Notebook', r'jupyter'],
        "paths": [r'/tree', r'/lab'],
        "category": "Admin Panel",
    },
    "RStudio Server": {
        "html": [r'RStudio Server', r'rstudio'],
        "paths": [r'/rstudio', r'/auth-sign-in'],
        "category": "Admin Panel",
    },
    "OpenWebUI": {
        "html": [r'OpenWebUI', r'openwebui'],
        "paths": [r'/openwebui', r'/auth/login'],
        "category": "Admin Panel",
    },
    "Uptime Kuma": {
        "html": [r'Uptime Kuma', r'uptime-kuma'],
        "paths": [r'/status', r'/dashboard'],
        "category": "Monitoring",
    },
    "Kasm Workspaces": {
        "html": [r'Kasm Workspaces', r'kasm'],
        "paths": [r'/login', r'/#/login'],
        "category": "Admin Panel",
    },
    "Portainer": {
        "html": [r'Portainer', r'portainer'],
        "paths": [r'/portainer', r'/#!/auth'],
        "category": "Admin Panel",
    },
    "Rancher": {
        "html": [r'Rancher', r'rancher'],
        "paths": [r'/dashboard', r'/login'],
        "category": "Admin Panel",
    },
    "Harbor": {
        "html": [r'Harbor', r'harbor'],
        "paths": [r'/harbor', r'/harbor/sign-in'],
        "category": "Admin Panel",
    },
    "GitLab": {
        "html": [r'GitLab', r'gitlab'],
        "paths": [r'/users/sign_in', r'/gitlab'],
        "category": "Admin Panel",
    },
    "Gitea": {
        "html": [r'Gitea', r'gitea'],
        "paths": [r'/user/login', r'/gitea'],
        "category": "Admin Panel",
    },
    "Jenkins": {
        "html": [r'Jenkins', r'jenkins'],
        "paths": [r'/jenkins', r'/login'],
        "category": "Admin Panel",
    },
    "TeamCity": {
        "html": [r'TeamCity', r'teamcity'],
        "paths": [r'/login.html', r'/teamcity'],
        "category": "Admin Panel",
    },
    "Bitbucket": {
        "html": [r'Bitbucket', r'bitbucket'],
        "paths": [r'/login', r'/bitbucket'],
        "category": "Admin Panel",
    },
    "Confluence": {
        "html": [r'Confluence', r'confluence'],
        "paths": [r'/login.action', r'/confluence'],
        "category": "Admin Panel",
    },
    "Jira": {
        "html": [r'Jira', r'jira'],
        "paths": [r'/login.jsp', r'/jira'],
        "category": "Admin Panel",
    },
    "Redmine": {
        "html": [r'Redmine', r'redmine'],
        "paths": [r'/login', r'/redmine'],
        "category": "Admin Panel",
    },
    "Mattermost": {
        "html": [r'Mattermost', r'mattermost'],
        "paths": [r'/signup_user_complete', r'/mattermost'],
        "category": "Admin Panel",
    },
    "Rocket.Chat": {
        "html": [r'Rocket.Chat', r'rocketchat'],
        "paths": [r'/home', r'/rocketchat'],
        "category": "Admin Panel",
    },
    "Nextcloud": {
        "html": [r'Nextcloud', r'nextcloud'],
        "paths": [r'/nextcloud', r'/login'],
        "category": "Admin Panel",
    },
    "OwnCloud": {
        "html": [r'OwnCloud', r'owncloud'],
        "paths": [r'/owncloud', r'/login'],
        "category": "Admin Panel",
    },
    "Pydio": {
        "html": [r'Pydio', r'pydio'],
        "paths": [r'/pydio', r'/login'],
        "category": "Admin Panel",
    },
    "OpenMediaVault": {
        "html": [r'OpenMediaVault', r'omv'],
        "paths": [r'/omv', r'/login'],
        "category": "Admin Panel",
    },
    "FreeNAS": {
        "html": [r'FreeNAS', r'freenas'],
        "paths": [r'/ui', r'/login'],
        "category": "Admin Panel",
    },
    "Mikrotik RouterOS": {
        "html": [r'MikroTik', r'routeros'],
        "paths": [r'/webfig', r'/login'],
        "category": "Admin Panel",
    },
    "pfSense": {
        "html": [r'pfSense', r'pfsense'],
        "paths": [r'/diag', r'/system_usermanager.php'],
        "category": "Admin Panel",
    },
    "OPNsense": {
        "html": [r'OPNsense', r'opnsense'],
        "paths": [r'/diag', r'/ui/'],
        "category": "Admin Panel",
    },
    "Sophos UTM": {
        "html": [r'Sophos UTM', r'sophos'],
        "paths": [r'/userportal', r'/login'],
        "category": "Admin Panel",
    },
    "FortiGate": {
        "html": [r'FortiGate', r'fortigate'],
        "paths": [r'/login', r'/ng'],
        "category": "Admin Panel",
    },
    "Cisco Meraki": {
        "html": [r'Meraki', r'cisco'],
        "paths": [r'/login', r'/nms'],
        "category": "Admin Panel",
    },
    "Ubiquiti UniFi": {
        "html": [r'UniFi', r'unifi'],
        "paths": [r'/manage', r'/login'],
        "category": "Admin Panel",
    },
    "Roundcube": {
        "html": [r'Roundcube', r'roundcube'],
        "category": "Mail",
    },
    "Mailcow": {
        "html": [r'Mailcow', r'mailcow'],
        "category": "Mail",
    },
    "phpMyAdmin": {
        "html": [r'phpMyAdmin', r'phpmyadmin'],
        "paths": [r'/phpmyadmin', r'/phpMyAdmin', r'/pma', r'/sql'],
        "category": "Database Admin",
    },
    "Adminer": {
        "html": [r'Adminer', r'adminer'],
        "category": "Database Admin",
    },
    "Mautic": {
        "html": [r'Mautic', r'mautic'],
        "category": "Marketing",
    },
    "Discourse": {
        "html": [r'Discourse', r'discourse'],
        "category": "Forum",
    },
    "Flarum": {
        "html": [r'Flarum', r'flarum'],
        "category": "Forum",
    },

    # --- Massive expansion: CMS, portals, admin panels, SaaS, and tooling ---
    "Drupal 7": {
        "html": [r'drupal\.org', r'/sites/all/themes/', r'/misc/drupal.js'],
        "category": "CMS",
    },
    "Concrete CMS": {
        "html": [r'concrete5', r'/concrete/'],
        "category": "CMS",
    },
    "TYPO3": {
        "html": [r'TYPO3', r'/typo3/'],
        "category": "CMS",
    },
    "Umbraco": {
        "html": [r'Umbraco', r'umbraco'],
        "category": "CMS",
    },
    "MODX": {
        "html": [r'MODX', r'/manager/'],
        "category": "CMS",
    },
    "SilverStripe": {
        "html": [r'SilverStripe', r'silverstripe'],
        "category": "CMS",
    },
    "PrestaShop": {
        "html": [r'PrestaShop', r'prestashop'],
        "category": "CMS / E-Commerce",
    },
    "OpenCart": {
        "html": [r'OpenCart', r'opencart'],
        "category": "CMS / E-Commerce",
    },
    "osCommerce": {
        "html": [r'osCommerce', r'oscommerce'],
        "category": "CMS / E-Commerce",
    },
    "BigCommerce": {
        "html": [r'bigcommerce', r'cdn\.bigcommerce'],
        "category": "CMS / E-Commerce",
    },
    "WooCommerce": {
        "html": [r'woocommerce', r'/wp-content/plugins/woocommerce/'],
        "category": "CMS / E-Commerce",
    },
    "Moodle": {
        "html": [r'Moodle', r'/theme/image.php'],
        "category": "Learning Platform",
    },
    "Mautic": {
        "html": [r'Mautic', r'mautic'],
        "paths": [r'/s/mautic', r'/index.php/mautic'],
        "category": "Marketing",
    },
    "HubSpot": {
        "html": [r'hubspot', r'hubspotusercontent', r'hs-scripts\.com', r'hs-analytics'],
        "scripts": [r'hs-scripts\.com', r'hubspot'],
        "category": "Marketing",
    },
    "Mailchimp": {
        "html": [r'mailchimp', r'mc-embed'],
        "category": "Marketing",
    },
    "Sendinblue": {
        "html": [r'sendinblue', r'sib-cp'],
        "category": "Marketing",
    },
    "SEOmatic": {
        "html": [r'SEOmatic', r'seomatic'],
        "category": "SEO",
    },
    "Matomo Analytics": {
        "html": [r'matomo', r'_paq\.push'],
        "category": "Analytics",
    },
    "Piwik": {
        "html": [r'piwik', r'_paq\.push'],
        "category": "Analytics",
    },
    "Hotjar": {
        "html": [r'hotjar', r'hjid:'],
        "category": "Analytics",
    },
    "Intercom": {
        "html": [r'intercom', r'intercomSettings'],
        "category": "CRM / Chat",
    },
    "Tawk.to": {
        "html": [r'tawk', r'tawk\.to'],
        "category": "CRM / Chat",
    },
    "LiveChat": {
        "html": [r'livechat', r'lc\.widget'],
        "category": "CRM / Chat",
    },
    "Calendly": {
        "html": [r'calendly', r'calendly\.com'],
        "category": "Scheduling",
    },
    "Typeform": {
        "html": [r'typeform', r'typeform\.com'],
        "category": "Forms",
    },
    "Formspree": {
        "html": [r'formspree', r'formspree\.io'],
        "category": "Forms",
    },
    "Jotform": {
        "html": [r'jotform', r'jotform\.com'],
        "category": "Forms",
    },
    "Telerik UI": {
        "html": [r'telerik', r'kendo\.all'],
        "category": "UI Library",
    },
    "Material UI": {
        "html": [r'mui', r'@material-ui'],
        "category": "UI Library",
    },
    "Bulma": {
        "html": [r'bulma', r'bulma\.css'],
        "category": "CSS Framework",
    },
    "Foundation": {
        "html": [r'foundation', r'foundation\.min\.css'],
        "category": "CSS Framework",
    },
    "Semantic UI": {
        "html": [r'semantic-ui', r'semantic\.min\.css'],
        "category": "CSS Framework",
    },
    "AEM": {
        "html": [r'/etc.clientlibs/', r'Adobe Experience Manager', r'aem'],
        "category": "CMS",
    },
    "Liferay": {
        "html": [r'Liferay', r'liferay'],
        "category": "Portal",
    },
    "Oracle WebLogic": {
        "html": [r'WebLogic', r'weblogic'],
        "category": "Application Server",
    },
    "IBM WebSphere": {
        "html": [r'WebSphere', r'websphere'],
        "category": "Application Server",
    },
    "GlassFish": {
        "html": [r'GlassFish', r'glassfish'],
        "category": "Application Server",
    },
    "WildFly": {
        "html": [r'WildFly', r'wildfly'],
        "category": "Application Server",
    },
    "Jetty": {
        "html": [r'Jetty', r'jetty'],
        "category": "Web Server",
    },
    "Boa": {
        "html": [r'Boa', r'boa'],
        "category": "Web Server",
    },
    "Cherokee": {
        "html": [r'Cherokee', r'cherokee'],
        "category": "Web Server",
    },
    "traefik": {
        "headers": {"Server": r"traefik"},
        "category": "Reverse Proxy",
    },
    "HAProxy": {
        "headers": {"Server": r"HAProxy"},
        "category": "Load Balancer",
    },
    "Envoy": {
        "headers": {"Server": r"envoy"},
        "category": "Proxy",
    },
    "Cloudflare Tunnel": {
        "headers": {"Server": r"cloudflared"},
        "category": "CDN / Security",
    },
    "Akamai Ghost": {
        "headers": {"Server": r"AkamaiGHost"},
        "category": "CDN",
    },
    "F5 BIG-IP": {
        "html": [r'BIG-IP', r'F5'],
        "category": "Load Balancer",
    },
    "Nexus Repository": {
        "html": [r'Nexus Repository', r'nexus'],
        "paths": [r'/nexus', r'/repository'],
        "category": "Artifact Repository",
    },
    "Artifactory": {
        "html": [r'Artifactory', r'artifactory'],
        "paths": [r'/artifactory', r'/ui/repos'],
        "category": "Artifact Repository",
    },
    "Sonatype Nexus": {
        "html": [r'Sonatype', r'nexus'],
        "category": "Artifact Repository",
    },
    "Apache Airflow": {
        "html": [r'Airflow', r'airflow'],
        "category": "Data Platform",
    },
    "Superset": {
        "html": [r'Superset', r'superset'],
        "category": "Data Platform",
    },
    "DataDog": {
        "html": [r'datadoghq', r'datadog'],
        "category": "Monitoring",
    },
    "Sentry": {
        "html": [r'sentry', r'sentry.io'],
        "category": "Monitoring",
    },
    "Elastic Stack": {
        "html": [r'elasticsearch', r'kibana', r'elastic'],
        "category": "Monitoring",
    },
    "OpenTelemetry": {
        "html": [r'opentelemetry', r'otel'],
        "category": "Monitoring",
    },
    "Splunk Enterprise": {
        "html": [r'Splunk Enterprise', r'splunkd'],
        "category": "Monitoring",
    },
    "Apache Druid": {
        "html": [r'Druid', r'druid'],
        "category": "Data Platform",
    },
    "ClickHouse": {
        "html": [r'ClickHouse', r'clickhouse'],
        "category": "Database",
    },
    "CouchDB": {
        "html": [r'CouchDB', r'couchdb'],
        "category": "Database",
    },
    "Neo4j": {
        "html": [r'neo4j', r'Neo4j'],
        "category": "Database",
    },
    "Memcached": {
        "html": [r'Memcached', r'memcached'],
        "category": "Cache",
    },
    "Airtable": {
        "html": [r'airtable', r'airtable\.com'],
        "category": "SaaS",
    },
    "Notion": {
        "html": [r'notion', r'notion\.so'],
        "category": "SaaS",
    },
    "Trello": {
        "html": [r'trello', r'trello\.com'],
        "category": "SaaS",
    },
    "Asana": {
        "html": [r'asana', r'asana\.com'],
        "category": "SaaS",
    },
    "Slack": {
        "html": [r'slack', r'slack\.com'],
        "category": "SaaS",
    },
    "Dropbox": {
        "html": [r'dropbox', r'dropbox\.com'],
        "category": "SaaS",
    },
    "Google Workspace": {
        "html": [r'workspace\.google\.com', r'googleusercontent'],
        "category": "SaaS",
    },
    "Microsoft 365": {
        "html": [r'office\.com', r'sharepoint'],
        "category": "SaaS",
    },
    "Atlassian": {
        "html": [r'atlassian', r'jira', r'confluence'],
        "category": "SaaS",
    },
    "GitHub": {
        "html": [r'github\.com', r'githubusercontent'],
        "category": "DevOps",
    },
    "GitLab CE": {
        "html": [r'gitlab', r'gitlab-ce'],
        "category": "DevOps",
    },
    "Bitbucket Server": {
        "html": [r'bitbucket', r'bitbucketserver'],
        "category": "DevOps",
    },
    "Jenkins X": {
        "html": [r'jenkins-x', r'jenkinsx'],
        "category": "CI / CD",
    },
    "CircleCI": {
        "html": [r'circleci', r'circleci\.com'],
        "category": "CI / CD",
    },
    "Travis CI": {
        "html": [r'travis', r'travis-ci'],
        "category": "CI / CD",
    },
    "GoCD": {
        "html": [r'go-cd', r'gocd'],
        "category": "CI / CD",
    },
    "Bamboo": {
        "html": [r'Bamboo', r'bamboo'],
        "category": "CI / CD",
    },
    "Drone": {
        "html": [r'Drone', r'drone'],
        "category": "CI / CD",
    },
    "Woodstock": {
        "html": [r'woodstock', r'woodstock'],
        "category": "Framework",
    },
    "Apache Cocoon": {
        "html": [r'Apache Cocoon', r'cocoon'],
        "category": "Framework",
    },
    "Deno": {
        "html": [r'Deno', r'deno\.dev'],
        "category": "Language",
    },
    "Go": {
        "html": [r'Go', r'golang'],
        "category": "Language",
    },
    "Rust": {
        "html": [r'Rust', r'cargo'],
        "category": "Language",
    },
    "Scala": {
        "html": [r'Scala', r'scala'],
        "category": "Language",
    },
    "Erlang": {
        "html": [r'Erlang', r'erlang'],
        "category": "Language",
    },
    "Lua": {
        "html": [r'Lua', r'lua'],
        "category": "Language",
    },
    "Perl": {
        "html": [r'Perl', r'perl'],
        "category": "Language",
    },
    "Hadoop": {
        "html": [r'Hadoop', r'hadoop'],
        "category": "Data Platform",
    },
    "Spark": {
        "html": [r'Spark', r'spark'],
        "category": "Data Platform",
    },
    "TensorFlow": {
        "html": [r'TensorFlow', r'tensorflow'],
        "category": "AI / ML",
    },
    "PyTorch": {
        "html": [r'PyTorch', r'pytorch'],
        "category": "AI / ML",
    },
    "Scikit-learn": {
        "html": [r'scikit-learn', r'sklearn'],
        "category": "AI / ML",
    },
    "Jupyter": {
        "html": [r'Jupyter', r'jupyter'],
        "category": "Data Platform",
    },
    "RStudio": {
        "html": [r'RStudio', r'rstudio'],
        "category": "Data Platform",
    },
    "Shiny": {
        "html": [r'Shiny', r'shiny'],
        "category": "Data Platform",
    },
    "OpenMPI": {
        "html": [r'OpenMPI', r'mpi'],
        "category": "Infrastructure",
    },
    "Puppet": {
        "html": [r'Puppet', r'puppet'],
        "category": "Config Management",
    },
    "Ansible": {
        "html": [r'Ansible', r'ansible'],
        "category": "Config Management",
    },
    "Chef": {
        "html": [r'Chef', r'chef'],
        "category": "Config Management",
    },
    "SaltStack": {
        "html": [r'SaltStack', r'salt'],
        "category": "Config Management",
    },
    "Terraform": {
        "html": [r'Terraform', r'terraform'],
        "category": "Infrastructure",
    },
    "Kubernetes": {
        "html": [r'Kubernetes', r'kubernetes'],
        "category": "Container Orchestration",
    },
    "Docker": {
        "html": [r'Docker', r'docker'],
        "category": "Container Orchestration",
    },
    "Podman": {
        "html": [r'Podman', r'podman'],
        "category": "Container Orchestration",
    },
    "OpenShift": {
        "html": [r'OpenShift', r'openshift'],
        "category": "Container Orchestration",
    },
    "K3s": {
        "html": [r'K3s', r'k3s'],
        "category": "Container Orchestration",
    },
    "OpenStack": {
        "html": [r'OpenStack', r'openstack'],
        "category": "Cloud",
    },
    "OpenStack Horizon": {
        "html": [r'Horizon', r'openstack'],
        "paths": [r'/horizon', r'/auth/login'],
        "category": "Cloud",
    },
    "OpenStack Keystone": {
        "html": [r'Keystone', r'keystone'],
        "paths": [r'/v3/auth/tokens', r'/identity'],
        "category": "Cloud",
    },
    "OpenStack Nova": {
        "html": [r'Nova', r'nova'],
        "category": "Cloud",
    },
    "OpenStack Cinder": {
        "html": [r'Cinder', r'cinder'],
        "category": "Cloud",
    },
    "OpenStack Neutron": {
        "html": [r'Neutron', r'neutron'],
        "category": "Cloud",
    },
    "OpenStack Swift": {
        "html": [r'Swift', r'swift'],
        "category": "Cloud",
    },
    "OpenStack Glance": {
        "html": [r'Glance', r'glance'],
        "category": "Cloud",
    },
    "OpenStack Heat": {
        "html": [r'Heat', r'heat'],
        "category": "Cloud",
    },
    "OpenNebula": {
        "html": [r'OpenNebula', r'opennebula'],
        "paths": [r'/oneflow', r'/sunstone'],
        "category": "Cloud",
    },
    "Apache CloudStack": {
        "html": [r'CloudStack', r'cloudstack'],
        "paths": [r'/client', r'/login'],
        "category": "Cloud",
    },
    "Proxmox VE": {
        "html": [r'Proxmox', r'proxmox'],
        "paths": [r'/pve', r'/nodes'],
        "category": "Cloud",
    },
    "oVirt": {
        "html": [r'oVirt', r'ovirt'],
        "paths": [r'/ovirt-engine', r'/login'],
        "category": "Cloud",
    },
    "OpenShift": {
        "html": [r'OpenShift', r'openshift'],
        "paths": [r'/oauth', r'/console'],
        "category": "Cloud",
    },
    "OpenShift Console": {
        "html": [r'OpenShift Console', r'openshift'],
        "paths": [r'/console', r'/oauth'],
        "category": "Cloud",
    },
    "OpenVPN": {
        "html": [r'OpenVPN', r'openvpn'],
        "paths": [r'/admin', r'/login'],
        "category": "VPN / Remote Access",
    },
    "WireGuard": {
        "html": [r'WireGuard', r'wireguard'],
        "paths": [r'/wg', r'/login'],
        "category": "VPN / Remote Access",
    },
    "Tailscale": {
        "html": [r'Tailscale', r'tailscale'],
        "paths": [r'/login', r'/admin'],
        "category": "VPN / Remote Access",
    },
    "Zabbix": {
        "html": [r'Zabbix', r'zabbix'],
        "paths": [r'/zabbix', r'/index.php'],
        "category": "Monitoring",
    },
    "Nagios": {
        "html": [r'Nagios', r'nagios'],
        "paths": [r'/nagios', r'/cgi-bin/status.cgi'],
        "category": "Monitoring",
    },
    "Icinga": {
        "html": [r'Icinga', r'icinga'],
        "paths": [r'/icinga', r'/login'],
        "category": "Monitoring",
    },
    "LibreNMS": {
        "html": [r'LibreNMS', r'librenms'],
        "paths": [r'/librenms', r'/login'],
        "category": "Monitoring",
    },
    "NetBox": {
        "html": [r'NetBox', r'netbox'],
        "paths": [r'/netbox', r'/login'],
        "category": "Infrastructure",
    },
    "IPFire": {
        "html": [r'IPFire', r'ipfire'],
        "paths": [r'/cgi-bin/console.cgi', r'/login'],
        "category": "Firewall",
    },
    "OPNsense": {
        "html": [r'OPNsense', r'opnsense'],
        "paths": [r'/ui/', r'/diag'],
        "category": "Firewall",
    },
    "pfSense": {
        "html": [r'pfSense', r'pfsense'],
        "paths": [r'/diag', r'/system_usermanager.php'],
        "category": "Firewall",
    },
    "Sophos Firewall": {
        "html": [r'Sophos', r'sophos'],
        "paths": [r'/userportal', r'/login'],
        "category": "Firewall",
    },
    "FortiGate": {
        "html": [r'FortiGate', r'fortigate'],
        "paths": [r'/login', r'/ng'],
        "category": "Firewall",
    },
    "MikroTik": {
        "html": [r'MikroTik', r'routeros'],
        "paths": [r'/webfig', r'/login'],
        "category": "Router / Firewall",
    },
    "UniFi Controller": {
        "html": [r'UniFi', r'unifi'],
        "paths": [r'/manage', r'/login'],
        "category": "Network Admin",
    },
    "Cisco Meraki": {
        "html": [r'Meraki', r'cisco'],
        "paths": [r'/login', r'/nms'],
        "category": "Network Admin",
    },
    "CPanel": {
        "html": [r'cPanel', r'cpanel'],
        "paths": [r'/cpanel', r'/whm'],
        "category": "Hosting Panel",
    },
    "Plesk": {
        "html": [r'Plesk', r'plesk'],
        "paths": [r'/smb/web/plesk', r'/login_up.php'],
        "category": "Hosting Panel",
    },
    "DirectAdmin": {
        "html": [r'DirectAdmin', r'directadmin'],
        "paths": [r'/CMD_LOGIN', r'/CMD_HTTPD_CONF'],
        "category": "Hosting Panel",
    },
    "Virtualmin": {
        "html": [r'Virtualmin', r'virtualmin'],
        "paths": [r'/virtualmin', r'/login'],
        "category": "Hosting Panel",
    },
    "Webuzo": {
        "html": [r'Webuzo', r'webuzo'],
        "paths": [r'/webuzo', r'/login'],
        "category": "Hosting Panel",
    },
    "Printer Admin": {
        "html": [r'printer', r'Printer'],
        "paths": [r'/webman', r'/hp/deviceinfo'],
        "category": "Printer / IoT",
    },
    "HP Printer": {
        "html": [r'HP', r'Printer'],
        "paths": [r'/hp/deviceinfo', r'/index.htm'],
        "category": "Printer / IoT",
    },
    "Epson Web Config": {
        "html": [r'Epson', r'webconfig'],
        "paths": [r'/PRESENTATION/HTML/TOP/frameset.htm', r'/webconfig'],
        "category": "Printer / IoT",
    },
    "Brother Printer": {
        "html": [r'Brother', r'brother'],
        "paths": [r'/general/status.html', r'/home/'],
        "category": "Printer / IoT",
    },
    "D-Link Router": {
        "html": [r'D-Link', r'dlink'],
        "paths": [r'/setup.cgi', r'/login'],
        "category": "Router / Firewall",
    },
    "TP-Link Router": {
        "html": [r'TP-Link', r'tplink'],
        "paths": [r'/userRpm/LoginRpm.htm', r'/login'],
        "category": "Router / Firewall",
    },
    "Linksys Router": {
        "html": [r'Linksys', r'linksys'],
        "paths": [r'/Forms/rmLogin.asp', r'/login'],
        "category": "Router / Firewall",
    },
    "Asus Router": {
        "html": [r'Asus', r'asus'],
        "paths": [r'/Main_Login.asp', r'/login'],
        "category": "Router / Firewall",
    },
    "Netgear Router": {
        "html": [r'Netgear', r'netgear'],
        "paths": [r'/setup.cgi', r'/login'],
        "category": "Router / Firewall",
    },
    "Synology DSM": {
        "html": [r'Synology', r'dsm'],
        "paths": [r'/webman', r'/login'],
        "category": "NAS",
    },
    "QNAP QTS": {
        "html": [r'QNAP', r'qts'],
        "paths": [r'/cgi-bin/authLogin.cgi', r'/login'],
        "category": "NAS",
    },
    "TrueNAS": {
        "html": [r'TrueNAS', r'truenas'],
        "paths": [r'/ui', r'/login'],
        "category": "NAS",
    },
    "Asustor NAS": {
        "html": [r'Asustor', r'asustor'],
        "paths": [r'/login', r'/admin'],
        "category": "NAS",
    },
    "Western Digital My Cloud": {
        "html": [r'My Cloud', r'mycloud'],
        "paths": [r'/UI/login', r'/login'],
        "category": "NAS",
    },
    "IP Camera Admin": {
        "html": [r'camera', r'Camera'],
        "paths": [r'/cgi-bin/viewer/video.jpg', r'/login'],
        "category": "Printer / IoT",
    },
    "Axis Camera": {
        "html": [r'Axis', r'axis'],
        "paths": [r'/view/view.shtml', r'/login'],
        "category": "Printer / IoT",
    },
    "Hikvision Camera": {
        "html": [r'Hikvision', r'hikvision'],
        "paths": [r'/doc/page/login.asp', r'/login'],
        "category": "Printer / IoT",
    },
    "Dahua Camera": {
        "html": [r'Dahua', r'dahua'],
        "paths": [r'/cgi-bin/login.cgi', r'/login'],
        "category": "Printer / IoT",
    },
    "Reolink Camera": {
        "html": [r'Reolink', r'reolink'],
        "paths": [r'/cgi-bin/api.cgi', r'/login'],
        "category": "Printer / IoT",
    },
    "AVTech Camera": {
        "html": [r'AVTech', r'avtech'],
        "paths": [r'/cgi-bin/viewer/index.cgi', r'/login'],
        "category": "Printer / IoT",
    },
    "MikroTik Router": {
        "html": [r'MikroTik', r'routeros'],
        "paths": [r'/webfig', r'/login'],
        "category": "Router / Firewall",
    },
    "Ubiquiti EdgeRouter": {
        "html": [r'EdgeRouter', r'ubnt'],
        "paths": [r'/login', r'/setup'],
        "category": "Router / Firewall",
    },
    "Ubiquiti UniFi Protect": {
        "html": [r'UniFi Protect', r'unifiprotect'],
        "paths": [r'/protect', r'/login'],
        "category": "Printer / IoT",
    },
    "Smart Home Hub": {
        "html": [r'hub', r'Home Assistant'],
        "paths": [r'/lovelace', r'/api'],
        "category": "IoT / Automation",
    },
    "Home Assistant": {
        "html": [r'Home Assistant', r'homeassistant'],
        "paths": [r'/lovelace', r'/api'],
        "category": "IoT / Automation",
    },
    "OpenHAB": {
        "html": [r'OpenHAB', r'openhab'],
        "paths": [r'/basicui/app', r'/login'],
        "category": "IoT / Automation",
    },
    "Domoticz": {
        "html": [r'Domoticz', r'domoticz'],
        "paths": [r'/login', r'/json.htm'],
        "category": "IoT / Automation",
    },
    "Proxmox": {
        "html": [r'Proxmox', r'proxmox'],
        "category": "Virtualization",
    },
    "VMware": {
        "html": [r'VMware', r'vmware'],
        "category": "Virtualization",
    },
    "Xen": {
        "html": [r'Xen', r'xen'],
        "category": "Virtualization",
    },
    "OpenMediaVault": {
        "html": [r'OpenMediaVault', r'openmediavault'],
        "category": "Storage",
    },
    "TrueNAS": {
        "html": [r'TrueNAS', r'truenas'],
        "category": "Storage",
    },
    "Synology": {
        "html": [r'Synology', r'synology'],
        "category": "Storage",
    },
    "QNAP": {
        "html": [r'QNAP', r'qnap'],
        "category": "Storage",
    },
    "Plex": {
        "html": [r'Plex', r'plex'],
        "category": "Media",
    },
    "Jellyfin": {
        "html": [r'Jellyfin', r'jellyfin'],
        "category": "Media",
    },
    "Emby": {
        "html": [r'Emby', r'emby'],
        "category": "Media",
    },
    "Nextcloud": {
        "html": [r'Nextcloud', r'nextcloud'],
        "paths": [r'/nextcloud'],
        "category": "Collaboration",
    },
    "OwnCloud": {
        "html": [r'OwnCloud', r'owncloud'],
        "paths": [r'/owncloud'],
        "category": "Collaboration",
    },
    "Seafile": {
        "html": [r'Seafile', r'seafile'],
        "category": "Collaboration",
    },
    "OnlyOffice": {
        "html": [r'OnlyOffice', r'onlyoffice'],
        "category": "Collaboration",
    },
    "Mattermost": {
        "html": [r'Mattermost', r'mattermost'],
        "paths": [r'/signup_user_complete'],
        "category": "Collaboration",
    },
    "Rocket.Chat": {
        "html": [r'Rocket\.Chat', r'rocketchat'],
        "category": "Collaboration",
    },
    "MindsDB": {
        "html": [r'MindsDB', r'mindsdb'],
        "category": "AI / ML",
    },
    "OpenWebUI": {
        "html": [r'OpenWebUI', r'openwebui'],
        "category": "AI / ML",
    },
    "LibreOffice": {
        "html": [r'LibreOffice', r'libreoffice'],
        "category": "Office",
    },
    "Collabora": {
        "html": [r'Collabora', r'collabora'],
        "category": "Office",
    },
    "Paperless-ngx": {
        "html": [r'Paperless', r'paperless'],
        "category": "Document Management",
    },
    "BookStack": {
        "html": [r'BookStack', r'bookstack'],
        "category": "Wiki",
    },
    "DokuWiki": {
        "html": [r'DokuWiki', r'dokuwiki'],
        "category": "Wiki",
    },
    "MediaWiki": {
        "html": [r'MediaWiki', r'mediawiki'],
        "category": "Wiki",
    },
    "XWiki": {
        "html": [r'XWiki', r'xwiki'],
        "category": "Wiki",
    },
    "MantisBT": {
        "html": [r'MantisBT', r'mantis'],
        "category": "Bug Tracker",
    },
    "Redmine": {
        "html": [r'Redmine', r'redmine'],
        "category": "Project Management",
    },
    "YouTrack": {
        "html": [r'YouTrack', r'youtrack'],
        "category": "Project Management",
    },
    "Taiga": {
        "html": [r'Taiga', r'taiga'],
        "category": "Project Management",
    },
    "OpenProject": {
        "html": [r'OpenProject', r'openproject'],
        "category": "Project Management",
    },
    "Tuleap": {
        "html": [r'Tuleap', r'tuleap'],
        "category": "Project Management",
    },
    "MISP": {
        "html": [r'MISP', r'misp'],
        "category": "Threat Intelligence",
    },
    "TheHive": {
        "html": [r'TheHive', r'thehive'],
        "category": "Threat Intelligence",
    },
    "Cortex": {
        "html": [r'Cortex', r'cortex'],
        "category": "Threat Intelligence",
    },
    "Shinken": {
        "html": [r'Shinken', r'shinken'],
        "category": "Monitoring",
    },
    "LibreNMS": {
        "html": [r'LibreNMS', r'librenms'],
        "paths": [r'/librenms'],
        "category": "Monitoring",
    },
    "Pandora FMS": {
        "html": [r'Pandora', r'pandora'],
        "category": "Monitoring",
    },
    "Icinga": {
        "html": [r'Icinga', r'icinga'],
        "category": "Monitoring",
    },
    "PRTG": {
        "html": [r'PRTG', r'prtg'],
        "category": "Monitoring",
    },
    "OPNsense": {
        "html": [r'OPNsense', r'opnsense'],
        "category": "Firewall / Network",
    },
    "Mikrotik": {
        "html": [r'MikroTik', r'mikrotik'],
        "category": "Firewall / Network",
    },
    "Ubiquiti": {
        "html": [r'Ubiquiti', r'ubiquiti'],
        "category": "Firewall / Network",
    },
    "MikroTik RouterOS": {
        "html": [r'RouterOS', r'mikrotik'],
        "category": "Firewall / Network",
    },
    "OpenWRT": {
        "html": [r'OpenWrt', r'openwrt'],
        "category": "Firewall / Network",
    },
    "IPFire": {
        "html": [r'IPFire', r'ipfire'],
        "category": "Firewall / Network",
    },
    "Palo Alto": {
        "html": [r'Palo Alto', r'paloalto'],
        "category": "Firewall / Network",
    },
    "Cisco ASA": {
        "html": [r'Cisco ASA', r'cisco'],
        "category": "Firewall / Network",
    },
    "Fortinet": {
        "html": [r'Fortinet', r'fortinet'],
        "category": "Firewall / Network",
    },
    "Sophos": {
        "html": [r'Sophos', r'sophos'],
        "category": "Firewall / Network",
    },
    "ClearOS": {
        "html": [r'ClearOS', r'clearos'],
        "category": "Firewall / Network",
    },
    "Asterisk": {
        "html": [r'Asterisk', r'asterisk'],
        "category": "VoIP",
    },
    "FreePBX": {
        "html": [r'FreePBX', r'freepbx'],
        "category": "VoIP",
    },
    "FusionPBX": {
        "html": [r'FusionPBX', r'fusionpbx'],
        "category": "VoIP",
    },
    "3CX": {
        "html": [r'3CX', r'3cx'],
        "category": "VoIP",
    },
    "Pi-hole": {
        "html": [r'Pi-hole', r'pi-hole'],
        "category": "Network",
    },
    "Unifi": {
        "html": [r'UniFi', r'unifi'],
        "category": "Network",
    },
    "ESET": {
        "html": [r'ESET', r'eset'],
        "category": "Security",
    },
    "Sophos UTM": {
        "html": [r'Sophos UTM', r'sophos'],
        "category": "Security",
    },
    "Fail2ban": {
        "html": [r'Fail2ban', r'fail2ban'],
        "category": "Security",
    },
    "Snort": {
        "html": [r'Snort', r'snort'],
        "category": "Security",
    },
    "Suricata": {
        "html": [r'Suricata', r'suricata'],
        "category": "Security",
    },
    "ClamAV": {
        "html": [r'ClamAV', r'clamav'],
        "category": "Security",
    },
    "OpenVAS": {
        "html": [r'OpenVAS', r'openvas'],
        "category": "Security",
    },
    "OsTicket": {
        "html": [r'osTicket', r'osticket'],
        "category": "Help Desk",
    },
    "GLPI": {
        "html": [r'GLPI', r'glpi'],
        "category": "Help Desk",
    },
    "Zammad": {
        "html": [r'Zammad', r'zammad'],
        "category": "Help Desk",
    },
    "Freshdesk": {
        "html": [r'Freshdesk', r'freshdesk'],
        "category": "Help Desk",
    },
    "Zoho Desk": {
        "html": [r'Zoho', r'zoho'],
        "category": "Help Desk",
    },
    "Snipe-IT": {
        "html": [r'Snipe-IT', r'snipeit'],
        "category": "IT Asset Management",
    },
    "NetBox": {
        "html": [r'NetBox', r'netbox'],
        "paths": [r'/netbox'],
        "category": "Infrastructure",
    },
    "IPAM": {
        "html": [r'IPAM', r'ipam'],
        "category": "Infrastructure",
    },
    "Rundeck": {
        "html": [r'Rundeck', r'rundeck'],
        "paths": [r'/user/login', r'/menu/home'],
        "category": "Automation",
    },
    "Ansible Tower": {
        "html": [r'Ansible Tower', r'awx'],
        "category": "Automation",
    },
    "AWX": {
        "html": [r'AWX', r'awx'],
        "category": "Automation",
    },
    "Prowler": {
        "html": [r'Prowler', r'prowler'],
        "category": "Security",
    },
    "Wazuh": {
        "html": [r'Wazuh', r'wazuh'],
        "category": "Security",
    },
    "Velociraptor": {
        "html": [r'Velociraptor', r'velociraptor'],
        "category": "Security",
    },
    "Cobalt Strike": {
        "html": [r'Cobalt Strike', r'cobalt'],
        "category": "Security",
    },
    "Malleable C2": {
        "html": [r'Malleable', r'c2'],
        "category": "Security",
    },
    "Pulsar": {
        "html": [r'Pulsar', r'pulsar'],
        "category": "Messaging",
    },
    "NATS": {
        "html": [r'NATS', r'nats'],
        "category": "Messaging",
    },
    "Mosquitto": {
        "html": [r'Mosquitto', r'mosquitto'],
        "category": "Messaging",
    },
    "Emqx": {
        "html": [r'EMQX', r'emqx'],
        "category": "Messaging",
    },
    "Apache APISIX": {
        "html": [r'APISIX', r'apisix'],
        "category": "API Gateway",
    },
    "Kong": {
        "html": [r'Kong', r'kong'],
        "category": "API Gateway",
    },
    "Tyk": {
        "html": [r'Tyk', r'tyk'],
        "category": "API Gateway",
    },
    "Gravitee": {
        "html": [r'Gravitee', r'gravitee'],
        "category": "API Gateway",
    },
    "Wso2": {
        "html": [r'WSO2', r'wso2'],
        "category": "API Gateway",
    },
    "Nginx Proxy Manager": {
        "html": [r'Nginx Proxy Manager', r'nginxproxymanager'],
        "paths": [r'/admin', r'/nginx/proxy'],
        "category": "Proxy",
    },
    "Caddy": {
        "headers": {"Server": r"Caddy"},
        "html": [r'caddy', r'caddyserver'],
        "category": "Reverse Proxy",
    },

    # --- Extra recon-heavy services and appliance interfaces ---
    "OpenKM": {
        "html": [r'OpenKM', r'openkm'],
        "category": "Document Management",
    },
    "Alfresco": {
        "html": [r'Alfresco', r'alfresco'],
        "category": "Document Management",
    },
    "Liferay DXP": {
        "html": [r'Liferay DXP', r'liferay'],
        "category": "Portal",
    },
    "OpenCms": {
        "html": [r'OpenCms', r'opencms'],
        "category": "CMS",
    },
    "CMS Made Simple": {
        "html": [r'CMS Made Simple', r'cmsms'],
        "category": "CMS",
    },
    "ProcessWire": {
        "html": [r'ProcessWire', r'processwire'],
        "category": "CMS",
    },
    "Concrete5": {
        "html": [r'Concrete5', r'concrete5'],
        "category": "CMS",
    },
    "Monstra": {
        "html": [r'Monstra', r'monstra'],
        "category": "CMS",
    },
    "Pimcore": {
        "html": [r'Pimcore', r'pimcore'],
        "category": "CMS",
    },
    "Pterodactyl": {
        "html": [r'Pterodactyl', r'pterodactyl'],
        "paths": [r'/auth/login', r'/admin'],
        "category": "Game Server Panel",
    },
    "Pelican Panel": {
        "html": [r'Pelican', r'pelican'],
        "category": "Game Server Panel",
    },
    "Multicraft": {
        "html": [r'Multicraft', r'multicraft'],
        "category": "Game Server Panel",
    },
    "OpenGamePanel": {
        "html": [r'OpenGamePanel', r'opengamepanel'],
        "category": "Game Server Panel",
    },
    "Pterodactyl Panel": {
        "html": [r'Pterodactyl', r'pterodactyl'],
        "category": "Game Server Panel",
    },
    "Cockpit": {
        "html": [r'Cockpit', r'cockpit'],
        "category": "Server Admin",
    },
    "Proxmox VE": {
        "html": [r'Proxmox', r'proxmox'],
        "category": "Virtualization",
    },
    "XCP-ng": {
        "html": [r'XCP-ng', r'xcp'],
        "category": "Virtualization",
    },
    "oVirt": {
        "html": [r'oVirt', r'ovirt'],
        "category": "Virtualization",
    },
    "Hyper-V": {
        "html": [r'Hyper-V', r'hyperv'],
        "category": "Virtualization",
    },
    "OpenStack Horizon": {
        "html": [r'Horizon', r'openstack'],
        "category": "Cloud",
    },
    "OpenNebula": {
        "html": [r'OpenNebula', r'opennebula'],
        "category": "Cloud",
    },
    "EVE-NG": {
        "html": [r'EVE-NG', r'eve-ng'],
        "category": "Network Lab",
    },
    "GNS3": {
        "html": [r'GNS3', r'gns3'],
        "category": "Network Lab",
    },
    "PacketTracer": {
        "html": [r'PacketTracer', r'packettracer'],
        "category": "Network Lab",
    },
    "OpenWrt": {
        "html": [r'OpenWrt', r'openwrt'],
        "category": "Router",
    },
    "OPNsense": {
        "html": [r'OPNsense', r'opnsense'],
        "category": "Firewall / Network",
    },
    "MikroTik": {
        "html": [r'MikroTik', r'mikrotik'],
        "category": "Firewall / Network",
    },
    "pfSense": {
        "html": [r'pfSense', r'pfsense'],
        "category": "Firewall / Network",
    },
    "VyOS": {
        "html": [r'VyOS', r'vyos'],
        "category": "Firewall / Network",
    },
    "EdgeOS": {
        "html": [r'EdgeOS', r'edgeos'],
        "category": "Firewall / Network",
    },
    "MikroTik RouterOS": {
        "html": [r'RouterOS', r'mikrotik'],
        "category": "Firewall / Network",
    },
    "Zyxel": {
        "html": [r'Zyxel', r'zyxel'],
        "category": "Firewall / Network",
    },
    "D-Link": {
        "html": [r'D-Link', r'dlink'],
        "category": "Firewall / Network",
    },
    "Cisco IOS": {
        "html": [r'Cisco IOS', r'cisco'],
        "category": "Networking",
    },
    "Cisco ASA": {
        "html": [r'Cisco ASA', r'cisco'],
        "category": "Networking",
    },
    "Fortinet FortiGate": {
        "html": [r'FortiGate', r'fortinet'],
        "category": "Firewall / Network",
    },
    "Sophos Firewall": {
        "html": [r'Sophos Firewall', r'sophos'],
        "category": "Firewall / Network",
    },
    "ClearOS": {
        "html": [r'ClearOS', r'clearos'],
        "category": "Firewall / Network",
    },
    "Asterisk": {
        "html": [r'Asterisk', r'asterisk'],
        "category": "VoIP",
    },
    "FreePBX": {
        "html": [r'FreePBX', r'freepbx'],
        "category": "VoIP",
    },
    "FusionPBX": {
        "html": [r'FusionPBX', r'fusionpbx'],
        "category": "VoIP",
    },
    "3CX": {
        "html": [r'3CX', r'3cx'],
        "category": "VoIP",
    },
    "Aastra": {
        "html": [r'Aastra', r'aastra'],
        "category": "VoIP",
    },
    "Grandstream": {
        "html": [r'Grandstream', r'grandstream'],
        "category": "VoIP",
    },
    "Fritz!Box": {
        "html": [r'Fritz!Box', r'fritz'],
        "category": "Router",
    },
    "MikroTik Winbox": {
        "html": [r'Winbox', r'mikrotik'],
        "category": "Router",
    },
    "Pi-hole": {
        "html": [r'Pi-hole', r'pi-hole'],
        "category": "Network",
    },
    "AdGuard Home": {
        "html": [r'AdGuard', r'adguard'],
        "category": "Network",
    },
    "Unifi": {
        "html": [r'UniFi', r'unifi'],
        "category": "Network",
    },
    "Raspberry Pi": {
        "html": [r'Raspberry Pi', r'raspberrypi'],
        "category": "Hardware",
    },
    "OctoPrint": {
        "html": [r'OctoPrint', r'octoprint'],
        "category": "Hardware",
    },
    "Home Assistant": {
        "html": [r'Home Assistant', r'homeassistant'],
        "category": "IoT",
    },
    "OpenHAB": {
        "html": [r'OpenHAB', r'openhab'],
        "category": "IoT",
    },
    "Node-RED": {
        "html": [r'Node-RED', r'nodered'],
        "category": "IoT",
    },
    "Domoticz": {
        "html": [r'Domoticz', r'domoticz'],
        "category": "IoT",
    },
    "Mosquitto": {
        "html": [r'Mosquitto', r'mosquitto'],
        "category": "IoT",
    },
    "ESPHome": {
        "html": [r'ESPHome', r'esphome'],
        "category": "IoT",
    },
    "OpenMediaVault": {
        "html": [r'OpenMediaVault', r'openmediavault'],
        "category": "Storage",
    },
    "TrueNAS": {
        "html": [r'TrueNAS', r'truenas'],
        "category": "Storage",
    },
    "Synology DSM": {
        "html": [r'Synology DSM', r'synology'],
        "category": "Storage",
    },
    "QNAP QTS": {
        "html": [r'QNAP QTS', r'qnap'],
        "category": "Storage",
    },
    "XigmaNAS": {
        "html": [r'XigmaNAS', r'xigmanas'],
        "category": "Storage",
    },
    "OmniOS": {
        "html": [r'OmniOS', r'omnios'],
        "category": "Storage",
    },
    "Plex Media Server": {
        "html": [r'Plex Media Server', r'plex'],
        "category": "Media",
    },
    "Jellyfin": {
        "html": [r'Jellyfin', r'jellyfin'],
        "category": "Media",
    },
    "Emby": {
        "html": [r'Emby', r'emby'],
        "category": "Media",
    },
    "Navidrome": {
        "html": [r'Navidrome', r'navidrome'],
        "category": "Media",
    },
    "Subsonic": {
        "html": [r'Subsonic', r'subsonic'],
        "category": "Media",
    },
    "Ampache": {
        "html": [r'Ampache', r'ampache'],
        "category": "Media",
    },
    "FileBrowser": {
        "html": [r'FileBrowser', r'filebrowser'],
        "category": "File Sharing",
    },
    "SFTPGo": {
        "html": [r'SFTPGo', r'sftpgo'],
        "category": "File Sharing",
    },
    "Seafile": {
        "html": [r'Seafile', r'seafile'],
        "category": "File Sharing",
    },
    "Nextcloud": {
        "html": [r'Nextcloud', r'nextcloud'],
        "category": "Collaboration",
    },
    "OwnCloud": {
        "html": [r'OwnCloud', r'owncloud'],
        "category": "Collaboration",
    },
    "OnlyOffice": {
        "html": [r'OnlyOffice', r'onlyoffice'],
        "category": "Collaboration",
    },
    "Rocket.Chat": {
        "html": [r'Rocket.Chat', r'rocketchat'],
        "category": "Collaboration",
    },
    "Mattermost": {
        "html": [r'Mattermost', r'mattermost'],
        "category": "Collaboration",
    },
    "Mautic": {
        "html": [r'Mautic', r'mautic'],
        "category": "Marketing",
    },
    "Discourse": {
        "html": [r'Discourse', r'discourse'],
        "category": "Forum",
    },
    "Flarum": {
        "html": [r'Flarum', r'flarum'],
        "category": "Forum",
    },
    "MantisBT": {
        "html": [r'MantisBT', r'mantis'],
        "category": "Bug Tracker",
    },
    "Redmine": {
        "html": [r'Redmine', r'redmine'],
        "category": "Project Management",
    },
    "YouTrack": {
        "html": [r'YouTrack', r'youtrack'],
        "category": "Project Management",
    },
    "Taiga": {
        "html": [r'Taiga', r'taiga'],
        "category": "Project Management",
    },
    "OpenProject": {
        "html": [r'OpenProject', r'openproject'],
        "category": "Project Management",
    },
    "Tuleap": {
        "html": [r'Tuleap', r'tuleap'],
        "category": "Project Management",
    },
    "MISP": {
        "html": [r'MISP', r'misp'],
        "category": "Threat Intelligence",
    },
    "TheHive": {
        "html": [r'TheHive', r'thehive'],
        "category": "Threat Intelligence",
    },
    "Cortex": {
        "html": [r'Cortex', r'cortex'],
        "category": "Threat Intelligence",
    },
    "Wazuh": {
        "html": [r'Wazuh', r'wazuh'],
        "category": "Security",
    },
    "Velociraptor": {
        "html": [r'Velociraptor', r'velociraptor'],
        "category": "Security",
    },
    "OsTicket": {
        "html": [r'osTicket', r'osticket'],
        "category": "Help Desk",
    },
    "GLPI": {
        "html": [r'GLPI', r'glpi'],
        "category": "Help Desk",
    },
    "Zammad": {
        "html": [r'Zammad', r'zammad'],
        "category": "Help Desk",
    },
    "Freshdesk": {
        "html": [r'Freshdesk', r'freshdesk'],
        "category": "Help Desk",
    },
    "Snipe-IT": {
        "html": [r'Snipe-IT', r'snipeit'],
        "category": "IT Asset Management",
    },
    "Rundeck": {
        "html": [r'Rundeck', r'rundeck'],
        "category": "Automation",
    },
    "AWX": {
        "html": [r'AWX', r'awx'],
        "category": "Automation",
    },
    "Ansible Tower": {
        "html": [r'Ansible Tower', r'awx'],
        "category": "Automation",
    },
    "SaltStack": {
        "html": [r'SaltStack', r'salt'],
        "category": "Config Management",
    },
    "Puppet": {
        "html": [r'Puppet', r'puppet'],
        "category": "Config Management",
    },
    "Chef": {
        "html": [r'Chef', r'chef'],
        "category": "Config Management",
    },
    "Terraform": {
        "html": [r'Terraform', r'terraform'],
        "category": "Infrastructure",
    },
    "Kubernetes": {
        "html": [r'Kubernetes', r'kubernetes'],
        "category": "Container Orchestration",
    },
    "Docker": {
        "html": [r'Docker', r'docker'],
        "category": "Container Orchestration",
    },
    "Podman": {
        "html": [r'Podman', r'podman'],
        "category": "Container Orchestration",
    },
    "OpenShift": {
        "html": [r'OpenShift', r'openshift'],
        "category": "Container Orchestration",
    },
    "K3s": {
        "html": [r'K3s', r'k3s'],
        "category": "Container Orchestration",
    },
    "Talos": {
        "html": [r'Talos', r'talos'],
        "category": "Container Orchestration",
    },
    "Nomad": {
        "html": [r'Nomad', r'nomad'],
        "category": "Container Orchestration",
    },
    "Portainer": {
        "html": [r'Portainer', r'portainer'],
        "category": "Container Management",
    },
    "Rancher": {
        "html": [r'Rancher', r'rancher'],
        "category": "Container Orchestration",
    },
    "Harbor": {
        "html": [r'Harbor', r'harbor'],
        "category": "Container Registry",
    },
    "Quay": {
        "html": [r'Quay', r'quay'],
        "category": "Container Registry",
    },
    "Gitea": {
        "html": [r'Gitea', r'gitea'],
        "category": "DevOps",
    },
    "GitBucket": {
        "html": [r'GitBucket', r'gitbucket'],
        "category": "DevOps",
    },
    "Gogs": {
        "html": [r'Gogs', r'gogs'],
        "category": "DevOps",
    },
    "Phabricator": {
        "html": [r'Phabricator', r'phabricator'],
        "category": "DevOps",
    },
    "Bitbucket Server": {
        "html": [r'Bitbucket Server', r'bitbucket'],
        "category": "DevOps",
    },
    "TeamCity": {
        "html": [r'TeamCity', r'teamcity'],
        "category": "CI / CD",
    },
    "Bamboo": {
        "html": [r'Bamboo', r'bamboo'],
        "category": "CI / CD",
    },
    "GoCD": {
        "html": [r'GoCD', r'gocd'],
        "category": "CI / CD",
    },
    "Drone": {
        "html": [r'Drone', r'drone'],
        "category": "CI / CD",
    },
    "Jenkins X": {
        "html": [r'Jenkins X', r'jenkinsx'],
        "category": "CI / CD",
    },
    "CircleCI": {
        "html": [r'CircleCI', r'circleci'],
        "category": "CI / CD",
    },
    "Travis CI": {
        "html": [r'Travis CI', r'travis'],
        "category": "CI / CD",
    },
    "GitHub": {
        "html": [r'GitHub', r'github'],
        "category": "DevOps",
    },
    "GitLab CE": {
        "html": [r'GitLab CE', r'gitlab'],
        "category": "DevOps",
    },
    "OpenSUSE": {
        "html": [r'OpenSUSE', r'opensuse'],
        "category": "OS",
    },
    "Ubuntu": {
        "html": [r'Ubuntu', r'ubuntu'],
        "category": "OS",
    },
    "Debian": {
        "html": [r'Debian', r'debian'],
        "category": "OS",
    },
    "CentOS": {
        "html": [r'CentOS', r'centos'],
        "category": "OS",
    },
    "Rocky Linux": {
        "html": [r'Rocky Linux', r'rockylinux'],
        "category": "OS",
    },
    "AlmaLinux": {
        "html": [r'AlmaLinux', r'almalinux'],
        "category": "OS",
    },
    "Fedora": {
        "html": [r'Fedora', r'fedora'],
        "category": "OS",
    },
    "FreeBSD": {
        "html": [r'FreeBSD', r'freebsd'],
        "category": "OS",
    },
    "OpenBSD": {
        "html": [r'OpenBSD', r'openbsd'],
        "category": "OS",
    },
    "NetBSD": {
        "html": [r'NetBSD', r'netbsd'],
        "category": "OS",
    },
    "Windows Server": {
        "html": [r'Windows Server', r'windowsserver'],
        "category": "OS",
    },
    "Microsoft IIS": {
        "html": [r'Microsoft IIS', r'iis'],
        "category": "Web Server",
    },
    "Nginx Plus": {
        "html": [r'Nginx Plus', r'nginx'],
        "category": "Web Server",
    },
    "Apache HTTP Server": {
        "html": [r'Apache HTTP Server', r'apache'],
        "category": "Web Server",
    },
    "LiteSpeed Web Server": {
        "html": [r'LiteSpeed Web Server', r'litespeed'],
        "category": "Web Server",
    },
    "Caddy Server": {
        "html": [r'Caddy Server', r'caddy'],
        "category": "Reverse Proxy",
    },
    "Traefik Proxy": {
        "html": [r'Traefik', r'traefik'],
        "category": "Reverse Proxy",
    },
    "HAProxy Load Balancer": {
        "html": [r'HAProxy', r'haproxy'],
        "category": "Load Balancer",
    },
    "Envoy Proxy": {
        "html": [r'Envoy', r'envoy'],
        "category": "Proxy",
    },
    "Nginx Proxy Manager": {
        "html": [r'Nginx Proxy Manager', r'nginxproxymanager'],
        "category": "Proxy",
    },
    "Tailscale": {
        "html": [r'Tailscale', r'tailscale'],
        "category": "VPN",
    },
    "WireGuard": {
        "html": [r'WireGuard', r'wireguard'],
        "category": "VPN",
    },
    "OpenVPN Access Server": {
        "html": [r'OpenVPN Access Server', r'openvpn'],
        "category": "VPN",
    },
    "SoftEther": {
        "html": [r'SoftEther', r'softether'],
        "category": "VPN",
    },
    "ZeroTier": {
        "html": [r'ZeroTier', r'zerotier'],
        "category": "VPN",
    },
    "Tor": {
        "html": [r'Tor', r'torproject'],
        "category": "Privacy",
    },
    "I2P": {
        "html": [r'I2P', r'i2p'],
        "category": "Privacy",
    },
    "OpenLDAP": {
        "html": [r'OpenLDAP', r'ldap'],
        "category": "Directory",
    },
    "FreeIPA": {
        "html": [r'FreeIPA', r'freeipa'],
        "category": "Directory",
    },
    "389 Directory Server": {
        "html": [r'389 Directory Server', r'389ds'],
        "category": "Directory",
    },
    "Samba": {
        "html": [r'Samba', r'samba'],
        "category": "File Sharing",
    },
    "CUPS": {
        "html": [r'CUPS', r'cups'],
        "category": "Printing",
    },
    "IPP": {
        "html": [r'IPP', r'ipp'],
        "category": "Printing",
    },
    "PaperCut": {
        "html": [r'PaperCut', r'papercut'],
        "category": "Printing",
    },
    "Nagios XI": {
        "html": [r'Nagios XI', r'nagios'],
        "category": "Monitoring",
    },
    "Zabbix Frontend": {
        "html": [r'Zabbix Frontend', r'zabbix'],
        "category": "Monitoring",
    },
    "Cacti Monitoring": {
        "html": [r'Cacti Monitoring', r'cacti'],
        "category": "Monitoring",
    },
    "LibreNMS Monitoring": {
        "html": [r'LibreNMS', r'librenms'],
        "category": "Monitoring",
    },
    "Prtg Network Monitor": {
        "html": [r'Prtg Network Monitor', r'prtg'],
        "category": "Monitoring",
    },
    "Auvik": {
        "html": [r'Auvik', r'auvik'],
        "category": "Monitoring",
    },
    "Datadog": {
        "html": [r'Datadog', r'datadog'],
        "category": "Monitoring",
    },
    "New Relic": {
        "html": [r'New Relic', r'newrelic'],
        "category": "Monitoring",
    },
    "Grafana Dashboard": {
        "html": [r'Grafana Dashboard', r'grafana'],
        "category": "Monitoring",
    },
    "Prometheus Metrics": {
        "html": [r'Prometheus Metrics', r'prometheus'],
        "category": "Monitoring",
    },
    "Kibana Dashboard": {
        "html": [r'Kibana Dashboard', r'kibana'],
        "category": "Monitoring",
    },
    "Elastic Search": {
        "html": [r'Elastic Search', r'elasticsearch'],
        "category": "Search Engine",
    },
    "OpenSearch Dashboard": {
        "html": [r'OpenSearch Dashboard', r'opensearch'],
        "category": "Search Engine",
    },
    "Apache Solr Admin": {
        "html": [r'Apache Solr Admin', r'solr'],
        "category": "Search Engine",
    },
    "Apache Tomcat Manager": {
        "html": [r'Apache Tomcat Manager', r'tomcat'],
        "category": "Web Server",
    },
    "Jenkins Blue Ocean": {
        "html": [r'Jenkins Blue Ocean', r'jenkins'],
        "category": "CI / CD",
    },
    "GitLab Omnibus": {
        "html": [r'GitLab Omnibus', r'gitlab'],
        "category": "DevOps",
    },
    "Gitea UI": {
        "html": [r'Gitea UI', r'gitea'],
        "category": "DevOps",
    },
    "Rundeck Community": {
        "html": [r'Rundeck Community', r'rundeck'],
        "category": "Automation",
    },
    "Portainer CE": {
        "html": [r'Portainer CE', r'portainer'],
        "category": "Container Management",
    },
    "Kubernetes Dashboard": {
        "html": [r'Kubernetes Dashboard', r'kubernetes'],
        "category": "Container Orchestration",
    },
    "OpenShift Console": {
        "html": [r'OpenShift Console', r'openshift'],
        "category": "Container Orchestration",
    },
    "SonarQube Server": {
        "html": [r'SonarQube Server', r'sonarqube'],
        "category": "Code Quality",
    },
    "Jira Software": {
        "html": [r'Jira Software', r'jira'],
        "category": "Project Management",
    },
    "Confluence Server": {
        "html": [r'Confluence Server', r'confluence'],
        "category": "Project Management",
    },
    "Atlassian Crowd": {
        "html": [r'Atlassian Crowd', r'atlassian'],
        "category": "Identity",
    },
    "Keycloak Admin": {
        "html": [r'Keycloak Admin', r'keycloak'],
        "category": "Identity",
    },
    "Vault UI": {
        "html": [r'Vault UI', r'vault'],
        "category": "Secrets Management",
    },
    "HashiCorp Consul": {
        "html": [r'HashiCorp Consul', r'consul'],
        "category": "Service Discovery",
    },
    "HashiCorp Nomad": {
        "html": [r'HashiCorp Nomad', r'nomad'],
        "category": "Service Discovery",
    },
    "HashiCorp Vault": {
        "html": [r'HashiCorp Vault', r'vault'],
        "category": "Secrets Management",
    },
    "OpenAM": {
        "html": [r'OpenAM', r'openam'],
        "category": "Identity",
    },
    "ForgeRock": {
        "html": [r'ForgeRock', r'forgerock'],
        "category": "Identity",
    },
    "OpenDJ": {
        "html": [r'OpenDJ', r'opendj'],
        "category": "Directory",
    },
    "OpenLDAP": {
        "html": [r'OpenLDAP', r'ldap'],
        "category": "Directory",
    },
    "Samba File Server": {
        "html": [r'Samba File Server', r'samba'],
        "category": "File Sharing",
    },
    "Webmin": {
        "html": [r'Webmin', r'webmin'],
        "category": "Admin Panel",
    },
    "Adminer": {
        "html": [r'Adminer', r'adminer'],
        "category": "Database Admin",
    },
    "pgAdmin": {
        "html": [r'pgAdmin', r'pgadmin'],
        "category": "Database Admin",
    },
    "RedisInsight": {
        "html": [r'RedisInsight', r'redis'],
        "category": "Database",
    },
    "Mongo Express": {
        "html": [r'Mongo Express', r'mongo'],
        "category": "Database",
    },
    "CouchDB Fauxton": {
        "html": [r'Fauxton', r'couchdb'],
        "category": "Database",
    },
    "RabbitMQ Management": {
        "html": [r'RabbitMQ Management', r'rabbitmq'],
        "category": "Messaging",
    },
    "Kafka Manager": {
        "html": [r'Kafka Manager', r'kafka'],
        "category": "Messaging",
    },
    "ActiveMQ Console": {
        "html": [r'ActiveMQ Console', r'activemq'],
        "category": "Messaging",
    },
    "Nifi UI": {
        "html": [r'Nifi UI', r'nifi'],
        "category": "Data Platform",
    },
    "OpenSearch Dashboards": {
        "html": [r'OpenSearch Dashboards', r'opensearch'],
        "category": "Search Engine",
    },
    "Apache Superset": {
        "html": [r'Apache Superset', r'superset'],
        "category": "Analytics",
    },
    "Kibana": {
        "html": [r'Kibana', r'kibana'],
        "paths": [r'/app/kibana'],
        "category": "Analytics",
    },
    "Grafana": {
        "html": [r'Grafana', r'grafana'],
        "paths": [r'/grafana', r'/login'],
        "category": "Monitoring",
    },
    "Prometheus": {
        "html": [r'Prometheus', r'prometheus'],
        "paths": [r'/graph'],
        "category": "Monitoring",
    },
    "Zabbix": {
        "html": [r'Zabbix', r'zabbix'],
        "paths": [r'/zabbix'],
        "category": "Monitoring",
    },
    "Cacti": {
        "html": [r'Cacti', r'cacti'],
        "paths": [r'/cacti'],
        "category": "Monitoring",
    },
    "Rundeck": {
        "html": [r'Rundeck', r'rundeck'],
        "paths": [r'/rundeck'],
        "category": "Automation",
    },
    "Portainer": {
        "html": [r'Portainer', r'portainer'],
        "paths": [r'/portainer'],
        "category": "Container Mgmt",
    },
    "Rancher": {
        "html": [r'Rancher', r'rancher'],
        "paths": [r'/dashboard'],
        "category": "Container Mgmt",
    },
    "Harbor": {
        "html": [r'Harbor', r'harbor'],
        "paths": [r'/harbor'],
        "category": "Container Registry",
    },
    "GitLab": {
        "html": [r'GitLab', r'gitlab'],
        "paths": [r'/users/sign_in'],
        "category": "DevOps",
    },
    "Gitea": {
        "html": [r'Gitea', r'gitea'],
        "paths": [r'/user/login'],
        "category": "DevOps",
    },
    "Jenkins": {
        "html": [r'Jenkins', r'jenkins'],
        "paths": [r'/jenkins'],
        "category": "CI/CD",
    },
    "TeamCity": {
        "html": [r'TeamCity', r'teamcity'],
        "paths": [r'/login.html'],
        "category": "CI/CD",
    },
    "Bitbucket": {
        "html": [r'Bitbucket', r'bitbucket'],
        "paths": [r'/login'],
        "category": "DevOps",
    },
    "Confluence": {
        "html": [r'Confluence', r'confluence'],
        "paths": [r'/login.action'],
        "category": "Collaboration",
    },
    "Jira": {
        "html": [r'Jira', r'jira'],
        "paths": [r'/login.jsp'],
        "category": "Project Mgmt",
    },
    "Redmine": {
        "html": [r'Redmine', r'redmine'],
        "paths": [r'/login'],
        "category": "Project Mgmt",
    },
    "Mattermost": {
        "html": [r'Mattermost', r'mattermost'],
        "paths": [r'/signup_user_complete'],
        "category": "Collaboration",
    },
    "Rocket.Chat": {
        "html": [r'Rocket.Chat', r'rocketchat'],
        "paths": [r'/home'],
        "category": "Collaboration",
    },
    "Nextcloud": {
        "html": [r'Nextcloud', r'nextcloud'],
        "paths": [r'/nextcloud'],
        "category": "File Sharing",
    },
    "OwnCloud": {
        "html": [r'OwnCloud', r'owncloud'],
        "paths": [r'/owncloud'],
        "category": "File Sharing",
    },
    "Pydio": {
        "html": [r'Pydio', r'pydio'],
        "paths": [r'/pydio'],
        "category": "File Sharing",
    },
    "Samba File Server": {
        "html": [r'Samba File Server', r'samba'],
        "category": "File Sharing",
    },
    "OpenMediaVault": {
        "html": [r'OpenMediaVault', r'omv'],
        "paths": [r'/omv'],
        "category": "NAS",
    },
    "FreeNAS": {
        "html": [r'FreeNAS', r'freenas'],
        "paths": [r'/ui'],
        "category": "NAS",
    },
    "Metabase": {
        "html": [r'Metabase', r'metabase'],
        "category": "Analytics",
    },
    "Airflow UI": {
        "html": [r'Airflow UI', r'airflow'],
        "category": "Data Platform",
    },
    "Jupyter Notebook": {
        "html": [r'Jupyter Notebook', r'jupyter'],
        "category": "Data Platform",
    },
    "RStudio Server": {
        "html": [r'RStudio Server', r'rstudio'],
        "category": "Data Platform",
    },
    "Apache Zeppelin": {
        "html": [r'Apache Zeppelin', r'zeppelin'],
        "category": "Data Platform",
    },
    "OpenWebUI": {
        "html": [r'OpenWebUI', r'openwebui'],
        "category": "AI / ML",
    },
    "MindsDB": {
        "html": [r'MindsDB', r'mindsdb'],
        "category": "AI / ML",
    },
    "TensorFlow Serving": {
        "html": [r'TensorFlow Serving', r'tensorflow'],
        "category": "AI / ML",
    },
    "PyTorch Serve": {
        "html": [r'PyTorch Serve', r'pytorch'],
        "category": "AI / ML",
    },
}

for name, signature in EXTENDED_SIGNATURES.items():
    if name in SIGNATURES:
        current = SIGNATURES[name]
        current.update(signature)
        for key, value in signature.items():
            if key in {"html", "headers", "meta", "scripts", "cookies", "paths"}:
                existing = current.get(key)
                if isinstance(existing, list) and isinstance(value, list):
                    current[key] = existing + value
                elif isinstance(existing, dict) and isinstance(value, dict):
                    current[key] = {**existing, **value}
                else:
                    current[key] = value
        continue
    SIGNATURES[name] = signature


def _compile_pattern(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return re.compile(value, re.IGNORECASE)
        except re.error:
            return re.compile(re.escape(value), re.IGNORECASE)
    if isinstance(value, list):
        return [_compile_pattern(v) for v in value if isinstance(v, (str, re.Pattern))]
    if isinstance(value, dict):
        return {k: _compile_pattern(v) for k, v in value.items()}
    return value


def _extract_literals(pattern: str) -> set[str]:
    raw = pattern
    if not isinstance(raw, str):
        raw = str(raw)
    tokens = re.split(r"[^A-Za-z0-9_./-]", raw)
    return {token.lower() for token in tokens if len(token) >= 3}


def _compile_signature(signature: dict) -> dict:
    compiled = {}
    for key, value in signature.items():
        if key in {"headers", "cookies", "html", "scripts", "meta", "paths"}:
            compiled[key] = _compile_pattern(value)
        else:
            compiled[key] = value
    return compiled


COMPILED_SIGNATURES = {name: _compile_signature(sig) for name, sig in SIGNATURES.items()}

SIGNATURES_BY_HEADER: dict[str, list[str]] = {}
SIGNATURES_BY_META: dict[str, list[str]] = {}
SIGNATURES_BY_COOKIE_TOKEN: dict[str, list[str]] = {}
SIGNATURES_BY_SCRIPT_TOKEN: dict[str, list[str]] = {}
SIGNATURES_BY_HTML_TOKEN: dict[str, list[str]] = {}
SIGNATURES_BY_PATH_TOKEN: dict[str, list[str]] = {}

for name, sig in COMPILED_SIGNATURES.items():
    for header_name in sig.get("headers", {}):
        SIGNATURES_BY_HEADER.setdefault(header_name.lower(), []).append(name)
    for meta_name in sig.get("meta", {}):
        SIGNATURES_BY_META.setdefault(meta_name.lower(), []).append(name)
    for cookie_pattern in sig.get("cookies", []):
        for token in _extract_literals(cookie_pattern.pattern if hasattr(cookie_pattern, "pattern") else str(cookie_pattern)):
            SIGNATURES_BY_COOKIE_TOKEN.setdefault(token, []).append(name)
    for script_pattern in sig.get("scripts", []):
        for token in _extract_literals(script_pattern.pattern if hasattr(script_pattern, "pattern") else str(script_pattern)):
            SIGNATURES_BY_SCRIPT_TOKEN.setdefault(token, []).append(name)
    for html_pattern in sig.get("html", []):
        for token in _extract_literals(html_pattern.pattern if hasattr(html_pattern, "pattern") else str(html_pattern)):
            SIGNATURES_BY_HTML_TOKEN.setdefault(token, []).append(name)
    for path_pattern in sig.get("paths", []):
        for token in _extract_literals(path_pattern.pattern if hasattr(path_pattern, "pattern") else str(path_pattern)):
            SIGNATURES_BY_PATH_TOKEN.setdefault(token, []).append(name)
