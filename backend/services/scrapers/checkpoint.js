const { EventSource } = require('eventsource');

function startCheckpoint(broadcast) {
  console.log("[Checkpoint] Connecting to SSE feed...");
  
  const es = new EventSource('https://threatmap-api.checkpoint.com/ThreatMap/api/feed');

  es.onopen = () => {
    console.log("[Checkpoint] Connected to SSE feed");
  };

  es.addEventListener('attack', (e) => {
    try {
      const data = JSON.parse(e.data);
      // Validate
      if (!data.a_t || !data.s_la || !data.d_la) return;

      const mappedEvent = {
        a_c: data.a_c || 1,
        a_n: data.a_n || 'Checkpoint Threat',
        a_t: (['exploit', 'malware', 'phishing'].includes(data.a_t) ? data.a_t : 'exploit'),
        s_co: data.s_co || 'UN',
        s_la: data.s_la || 0,
        s_lo: data.s_lo || 0,
        d_co: data.d_co || 'UN',
        d_la: data.d_la || 0,
        d_lo: data.d_lo || 0
      };

      // Since Checkpoint is the authentic source of this format, it perfectly maps
      broadcast('attack', mappedEvent, 'checkpoint');
    } catch (err) {
      // ignore parse errors
    }
  });

  es.onerror = (err) => {
    console.error("[Checkpoint] SSE error");
  };
}

module.exports = { startCheckpoint };
