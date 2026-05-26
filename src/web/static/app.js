function resinApp() {
  return {
    events: [],
    searchQuery: '',
    serviceFilter: '',
    connected: false,
    eventSource: null,

    init() {
      this.fetchEvents();
      this.connectSSE();
      // Fallback polling in case SSE fails silently
      setInterval(() => this.fetchEvents(), 10000);
    },

    async fetchEvents() {
      const params = new URLSearchParams();
      if (this.searchQuery) params.set('q', this.searchQuery);
      if (this.serviceFilter) params.set('service', this.serviceFilter);
      params.set('limit', '200');

      try {
        const resp = await fetch('/api/events?' + params.toString());
        const data = await resp.json();
        this.events = data.map(e => ({ ...e, expanded: false }));
      } catch (err) {
        console.error('fetch error:', err);
      }
    },

    connectSSE() {
      if (this.eventSource) {
        this.eventSource.close();
      }

      this.eventSource = new EventSource('/events/stream');

      this.eventSource.onopen = () => {
        this.connected = true;
      };

      this.eventSource.onmessage = (e) => {
        try {
          const newEvents = JSON.parse(e.data);
          for (const evt of newEvents) {
            evt.expanded = false;
            // Only add if not filtered out
            if (this.serviceFilter && evt.service !== this.serviceFilter) continue;
            if (this.searchQuery) {
              const q = this.searchQuery.toLowerCase();
              const match = (evt.source_ip || '').toLowerCase().includes(q)
                || (evt.username || '').toLowerCase().includes(q)
                || (evt.password || '').toLowerCase().includes(q)
                || (evt.action || '').toLowerCase().includes(q)
                || (evt.service || '').toLowerCase().includes(q);
              if (!match) continue;
            }
            this.events.unshift(evt);
          }
          // Keep max 500 events in view
          if (this.events.length > 500) {
            this.events = this.events.slice(0, 500);
          }
        } catch (err) {
          console.error('sse parse error:', err);
        }
      };

      this.eventSource.onerror = () => {
        this.connected = false;
        setTimeout(() => this.connectSSE(), 5000);
      };
    },

    formatTime(iso) {
      if (!iso) return '';
      const d = new Date(iso);
      return d.toLocaleString();
    }
  };
}
