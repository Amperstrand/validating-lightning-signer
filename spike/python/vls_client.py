"""Asyncio JSON-lines client for the vls-bridge sidecar (Electrum-shaped consumer)."""

import asyncio
import json


class VlsBridgeError(RuntimeError):
    pass


class VlsBridgeClient:
    def __init__(self, path: str):
        self.path = path
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self._id = 0

    async def connect(self) -> "VlsBridgeClient":
        self.reader, self.writer = await asyncio.open_unix_connection(self.path)
        return self

    async def call(self, method: str, params: dict | None = None) -> dict:
        if self.reader is None or self.writer is None:
            raise VlsBridgeError("not connected")
        self._id += 1
        request = {"id": self._id, "method": method, "params": params or {}}
        self.writer.write((json.dumps(request) + "\n").encode())
        await self.writer.drain()
        line = await self.reader.readline()
        if not line:
            raise VlsBridgeError(f"bridge closed connection during {method}")
        response = json.loads(line)
        if "error" in response:
            raise VlsBridgeError(f"{method}: {response['error']}")
        return response.get("result", {})

    async def close(self) -> None:
        if self.writer is not None:
            self.writer.close()
            await self.writer.wait_closed()
