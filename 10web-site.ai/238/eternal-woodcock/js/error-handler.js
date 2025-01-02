// Advanced Resource Error Handler with Enhanced Protection
(function() {
    'use strict';

    // Early protection before DOM loads
    const protectionConfig = {
        enabled: true,
        debugMode: false,
        blockConsoleErrors: true,
        blockTracking: true,
        blockAds: true,
        allowEssentialCookies: true
    };

    // Prevent tampering with protection config
    Object.freeze(protectionConfig);

    // Enhanced console management
    const consoleManager = {
        originalConsole: {
            log: console.log,
            error: console.error,
            warn: console.warn,
            debug: console.debug
        },

        shouldBlock: function(args) {
            const message = args.join(' ').toLowerCase();
            return message.includes('err_blocked_by_client') ||
                   message.includes('failed to load') ||
                   message.includes('gtm') ||
                   message.includes('analytics') ||
                   message.includes('tracking') ||
                   message.includes('pixel') ||
                   message.includes('error loading script');
        },

        init: function() {
            if (protectionConfig.blockConsoleErrors) {
                console.error = (...args) => {
                    if (!this.shouldBlock(args)) {
                        this.originalConsole.error.apply(console, args);
                    }
                };
                console.warn = (...args) => {
                    if (!this.shouldBlock(args)) {
                        this.originalConsole.warn.apply(console, args);
                    }
                };
            }

            if (protectionConfig.debugMode) {
                console.debug = this.originalConsole.debug;
            } else {
                console.debug = () => {};
            }
        }
    };

    // Enhanced tracking protection
    const trackingProtection = {
        blockedDomains: [
            // Analytics and Tracking
            'googletagmanager.com',
            'google-analytics.com',
            'analytics.google.com',
            'analytics',
            'segment.com',
            'segment.io',
            'mixpanel.com',

            // Social Media Tracking
            'facebook.net',
            'facebook.com',
            'twitter.com',
            'ads-twitter.com',
            'linkedin.com',
            'tiktok.com',
            'snap.com',
            'pinterest.com',

            // Advertising
            'doubleclick.net',
            'adsystem.com',
            'adnxs.com',
            'advertising',
            'adroll.com',
            'criteo.com',
            'outbrain.com',

            // Marketing Tools
            'firstpromoter.com',
            'redditstatic.com',
            'hsforms.com',
            'hs-scripts.com',
            'hs-analytics',
            'hubspot.com',
            'marketo.com',
            'salesforce.com',

            // Heat Mapping and Session Recording
            'hotjar.com',
            'mouseflow.com',
            'clarity.ms',
            'luckyorange.com',
            'crazyegg.com',

            // Generic Tracking Terms
            'tracking',
            'telemetry',
            'metrics',
            'pixel',
            'beacon',
            'collect'
        ],

        // Comprehensive stubs for all tracking services
        trackingStubs: {
            // Google
            gtag: () => {},
            ga: () => {},
            google_tag_manager: {},
            GoogleAnalyticsObject: true,
            __ga__: () => {},
            
            // Facebook
            fbq: () => {},
            fb: () => {},
            fbevents: () => {},
            
            // Other Social Media
            twq: () => {},
            ttq: () => {},
            lintrk: () => {},
            rdt: () => {},
            pintrk: () => {},
            snaptr: () => {},
            
            // Marketing Tools
            hsq: () => {},
            hbspt: {
                forms: { create: () => {} }
            },
            
            // Analytics
            analytics: () => {},
            _satellite: {},
            dataLayer: [],
            
            // Session Recording
            hj: () => {},
            clarity: () => {},
            
            // Generic
            trackEvent: () => {},
            trackPageview: () => {},
            trackCustom: () => {}
        },

        setupStubs: function() {
            Object.entries(this.trackingStubs).forEach(([key, value]) => {
                if (!window[key]) {
                    try {
                        Object.defineProperty(window, key, {
                            value,
                            writable: false,
                            configurable: false
                        });
                    } catch (e) {
                        window[key] = value;
                    }
                }
            });
        },

        isDomainBlocked: function(url) {
            if (!url) return false;
            const urlLower = url.toLowerCase();
            return this.blockedDomains.some(domain => 
                urlLower.includes(domain) || 
                urlLower.includes(domain.replace(/\./g, '-'))
            );
        }
    };

    // Network request interceptor
    const networkInterceptor = {
        init: function() {
            // Intercept XHR
            const originalXHR = window.XMLHttpRequest;
            window.XMLHttpRequest = function() {
                const xhr = new originalXHR();
                const originalOpen = xhr.open;
                const originalSend = xhr.send;

                xhr.open = function(method, url) {
                    if (trackingProtection.isDomainBlocked(url)) {
                        throw new Error('Request blocked');
                    }
                    return originalOpen.apply(this, arguments);
                };

                xhr.send = function(data) {
                    if (data && typeof data === 'string' && trackingProtection.isDomainBlocked(data)) {
                        throw new Error('Request blocked');
                    }
                    return originalSend.apply(this, arguments);
                };

                return xhr;
            };

            // Intercept Fetch
            const originalFetch = window.fetch;
            window.fetch = function(resource, init) {
                const url = resource instanceof Request ? resource.url : resource;
                if (trackingProtection.isDomainBlocked(url)) {
                    return Promise.reject(new Error('Request blocked'));
                }
                return originalFetch.apply(this, arguments);
            };
        }
    };

    // Script injection blocker
    const scriptBlocker = {
        init: function() {
            const originalCreateElement = document.createElement;
            document.createElement = function(tagName) {
                const element = originalCreateElement.call(document, tagName);
                
                if (tagName.toLowerCase() === 'script') {
                    const originalSetAttribute = element.setAttribute;
                    element.setAttribute = function(name, value) {
                        if (value && typeof value === 'string' && 
                            (name === 'src' || name === 'data-src') && 
                            trackingProtection.isDomainBlocked(value)) {
                            return;
                        }
                        return originalSetAttribute.call(this, name, value);
                    };

                    Object.defineProperty(element, 'src', {
                        set(value) {
                            if (value && !trackingProtection.isDomainBlocked(value)) {
                                element.setAttribute('src', value);
                            }
                        },
                        get() {
                            return element.getAttribute('src');
                        }
                    });
                }
                return element;
            };
        }
    };

    // Initialize all protections
    function init() {
        consoleManager.init();
        trackingProtection.setupStubs();
        networkInterceptor.init();
        scriptBlocker.init();

        // Handle resource errors
        window.addEventListener('error', function(e) {
            if (e.target.tagName) {
                const url = e.target.src || e.target.href;
                if (url && trackingProtection.isDomainBlocked(url)) {
                    e.preventDefault();
                    if (protectionConfig.debugMode) {
                        console.debug('Blocked resource:', url);
                    }
                }
            }
        }, true);

        // Clean up existing error messages
        console.clear();

        if (protectionConfig.debugMode) {
            console.debug('Enhanced resource protection active');
        }
    }

    // Start protection immediately
    init();
})();

// Initialize consent management
function initConsentManagement() {
    const consentBanner = document.createElement('div');
    consentBanner.id = 'consent-banner';
    consentBanner.innerHTML = `
        <div class="consent-content">
            <p>We use cookies and similar technologies to enhance your experience. Some content may not load if blocked.</p>
            <button onclick="acceptAllCookies()">Accept All</button>
            <button onclick="acceptEssentialOnly()">Essential Only</button>
        </div>
    `;
    
    // Add styles for the consent banner
    const styles = document.createElement('style');
    styles.textContent = `
        #consent-banner {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: #f8f9fa;
            padding: 1rem;
            box-shadow: 0 -2px 10px rgba(0,0,0,0.1);
            z-index: 9999;
        }
        #consent-banner button {
            margin: 0.5rem;
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
    `;
    document.head.appendChild(styles);
    document.body.appendChild(consentBanner);
}

// Cookie consent functions
window.acceptAllCookies = function() {
    localStorage.setItem('cookieConsent', 'all');
    document.getElementById('consent-banner').style.display = 'none';
};

window.acceptEssentialOnly = function() {
    localStorage.setItem('cookieConsent', 'essential');
    document.getElementById('consent-banner').style.display = 'none';
};

// Check consent on load
document.addEventListener('DOMContentLoaded', function() {
    if (!localStorage.getItem('cookieConsent')) {
        initConsentManagement();
    }
});
