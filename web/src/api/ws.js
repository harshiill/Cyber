function resolveWsHost() {
  // Vite dev server is on :5173, FastAPI is on :8000. Anything else => same origin.
  if (location.host.includes('5173')) return 'localhost:8000'
  return location.host
}

/**
 * Create an auto-reconnecting WebSocket.
 *
 * @param {string} path  e.g. '/ws/alerts'
 * @param {(msg: any) => void} onMessage
 * @param {{ onStatus?: (state: 'connecting'|'open'|'closed') => void }} [opts]
 * @returns {{ close: () => void }}
 */
export function createWs(path, onMessage, { onStatus } = {}) {
  const host = resolveWsHost()
  const url  = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${host}${path}`
  let ws
  let reconnectDelay = 1000
  let closedByUser   = false
  let reconnectTimer = null

  function connect() {
    onStatus?.('connecting')
    ws = new WebSocket(url)
    ws.onopen = () => {
      reconnectDelay = 1000
      onStatus?.('open')
    }
    ws.onmessage = (e) => {
      try { onMessage(JSON.parse(e.data)) } catch { /* ignore malformed frames */ }
    }
    ws.onclose = () => {
      onStatus?.('closed')
      if (closedByUser) return
      reconnectTimer = setTimeout(connect, reconnectDelay)
      reconnectDelay = Math.min(reconnectDelay * 2, 16000)
    }
    ws.onerror = () => ws.close()
  }

  connect()
  return {
    close() {
      closedByUser = true
      clearTimeout(reconnectTimer)
      ws?.close()
    },
  }
}
