class WSService {
    constructor() {
        this.socket = null;
        this.clientId = "client_" + Math.random().toString(36).substr(2, 9);
        this.onMessageHandlers = [];
    }

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws?client_id=${this.clientId}`;

        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
            console.log("WebSocket Connected");
            this.notifyHandlers({ type: 'sys_connect' });
        };

        this.socket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.notifyHandlers(data);
            } catch (e) {
                console.error("WS Parse Error:", e);
            }
        };

        this.socket.onclose = () => {
            console.log("WebSocket Disconnected. Reconnecting in 5s...");
            this.notifyHandlers({ type: 'sys_disconnect' });
            setTimeout(() => this.connect(), 5000);
        };
    }

    onMessage(handler) {
        this.onMessageHandlers.push(handler);
    }

    notifyHandlers(data) {
        this.onMessageHandlers.forEach(h => h(data));
    }
}

window.WSService = new WSService();
