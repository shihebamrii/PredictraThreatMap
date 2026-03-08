const axios = require('axios');
const geoip = require('geoip-lite');

/**
 * Abuse.ch (URLhaus) Scraper
 * Fetches recent malicious URLs and their hosting IPs.
 */

async function startUrlhaus(broadcast) {
    console.log("[URLhaus] Scraper started. Polling every 60 seconds.");

    const poll = async () => {
        try {
            // Fetching recent malicious URLs from the last 3 days
            const response = await axios.get('https://urlhaus-api.abuse.ch/v1/urls/recent/');

            if (response.data && response.data.urls && Array.isArray(response.data.urls)) {
                console.log(`[URLhaus] Fetched ${response.data.urls.length} recent malicious URLs.`);

                // Take a small subset of the most recent ones to avoid flooding the map too aggressively
                const recentUrls = response.data.urls.slice(0, 50);

                recentUrls.forEach(item => {
                    // Extract the host/IP from the URL
                    let host = '';
                    try {
                        const url = new URL(item.url);
                        host = url.hostname;
                    } catch (e) {
                        // Fallback if URL parsing fails
                        return;
                    }

                    // GeoIP lookup for the host
                    const geo = geoip.lookup(host);

                    if (geo && geo.ll) {
                        const [lat, lon] = geo.ll;

                        // For URLhaus, we show it as a "detection" or "infection" at a specific location.
                        // We can visualize it as a source with a small random jitter for "destination" 
                        // to make it consistent with the existing arc visualization on the globe.
                        const mappedEvent = {
                            a_c: 1,
                            a_n: `[URLhaus] Malicious URL: ${item.threat || 'Malware Distribution'}`,
                            a_t: 'malware',
                            s_co: geo.country || 'UN',
                            s_la: lat,
                            s_lo: lon,
                            d_co: geo.country || 'UN',
                            d_la: lat + (Math.random() - 0.5) * 2,
                            d_lo: lon + (Math.random() - 0.5) * 2
                        };

                        broadcast('attack', mappedEvent, 'urlhaus');
                    }
                });
            }
        } catch (error) {
            console.error("[URLhaus] Error polling URLhaus API:", error.message);
        }
    };

    // Initial poll
    await poll();

    // URLhaus suggests polling every 5-60 minutes, let's do 60 seconds for a healthy balance in a demo
    setInterval(poll, 60000);
}

module.exports = { startUrlhaus };
