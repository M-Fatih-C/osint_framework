import json
from collections import defaultdict
from typing import Dict, List

from fastapi import WebSocket

from osint_framework.core.logger import logger

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = defaultdict(list)

    async def connect(self, ws: WebSocket, client_id: str):
        await ws.accept()
        self.active_connections[client_id].append(ws)
        logger.debug(f"WS Client {client_id} connected. Total: {len(self.active_connections[client_id])}")

    def disconnect(self, ws: WebSocket, client_id: str):
        if client_id in self.active_connections:
            if ws in self.active_connections[client_id]:
                self.active_connections[client_id].remove(ws)
            if not self.active_connections[client_id]:
                del self.active_connections[client_id]

    async def broadcast(self, data: dict):
        """Broadcasts a message to all connected clients."""
        text_data = json.dumps(data)
        dead_sockets = []
        for client_id, connections in self.active_connections.items():
            for ws in connections:
                try:
                    await ws.send_text(text_data)
                except Exception:
                    dead_sockets.append((client_id, ws))
                    
        for client_id, ws in dead_sockets:
            self.disconnect(ws, client_id)

ws_manager = ConnectionManager()
