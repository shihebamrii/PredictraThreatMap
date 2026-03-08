const axios = require('axios');
const geoip = require('geoip-lite');

/**
 * Abuse.ch (ThreatFox) Scraper
 * Fetches recent Indicators of Compromise (IoCs).
 */

async function startThreatFox(broadcast) {
    console.log("[ThreatFox] Scraper started. Polling every 30 seconds.");

    const poll = async () => {
        try {
            // ThreatFox API requires a POST request to get recent IoCs
            const response = await axios.post('https://threatfox-api.abuse.ch/api/v1/', {
                query: "get_recent",
                selector: 100
            });

            if (response.data && response.data.query_status === 'ok' && Array.isArray(response.data.data)) {
                console.log(`[ThreatFox] Fetched ${response.data.data.length} recent IoCs.`);

                // Take a subset for the map
                const recentIoCs = response.data.data.slice(0, 30);

                recentIoCs.forEach(item => {
                    // threat_control_panel uses ioc_value which could be IP:Port or Domain
                    let host = item.ioc_value;
                    if (host.includes(':')) {
                        host = host.split(':')[0];
                    }

                    // GeoIP lookup
                    const geo = geoip.lookup(host);

                    if (geo && geo.ll) {
                        const [lat, lon] = geo.ll;

                        // Map threat type to our categories
                        let a_t = 'malware';
                        if (item.threat_type_desc && item.threat_type_desc.toLowerCase().includes('phishing')) {
                            a_t = 'phishing';
                        } else if (item.threat_type_desc && (item.threat_type_desc.toLowerCase().includes('exploit') || item.threat_type_desc.toLowerCase().includes('c2'))) {
                            a_t = 'exploit';
                        }

                        const mappedEvent = {
                            a_c: 1,
                            a_n: `[ThreatFox] ${item.threat_type_desc || 'IoC Detected'}: ${item.malware_printable || 'Unknown Malware'}`,
                            a_t: a_t,
                            s_co: geo.country || 'UN',
                            s_la: lat,
                            s_lo: lon,
                            d_co: 'US', // Defaulting to a central target to ensure arc visibility
                            d_la: 37.0902 + (Math.random() - 0.5) * 10,
                            d_lo: -95.7129 + (Math.random() - 0.5) * 10
                        };

                        broadcast('attack', mappedEvent, 'threatfox');
                    }
                });
            }
        } catch (error) {
            console.error("[ThreatFox] Error polling ThreatFox API:", error.message);
        }
    };

    // Initial poll
    await poll();

    // Every 30 seconds for live feel
    setInterval(poll, 30000);
}

module.exports = { startThreatFox };
