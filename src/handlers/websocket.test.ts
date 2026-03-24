import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { websocketHandler } from './websocket'

type MockContext = {
  get: (key: string) => any
  req: {
    header: (name: string) => string | undefined
  }
  json: (data: unknown, status?: number) => Response
}

class FakeWebSocket {
  sent: string[] = []
  listeners: Record<string, Array<(event?: any) => void>> = {}

  accept() {}

  send(message: string) {
    this.sent.push(message)
  }

  addEventListener(type: string, handler: (event?: any) => void) {
    if (!this.listeners[type]) this.listeners[type] = []
    this.listeners[type].push(handler)
  }

  emit(type: string, event?: any) {
    for (const handler of this.listeners[type] || []) {
      handler(event)
    }
  }
}

describe('websocketHandler', () => {
  let originalWebSocketPair: any

  beforeEach(() => {
    vi.spyOn(globalThis, 'setInterval').mockReturnValue(1 as any)
    vi.spyOn(globalThis, 'clearInterval').mockImplementation(() => undefined)
    originalWebSocketPair = (globalThis as any).WebSocketPair
  })

  afterEach(() => {
    vi.restoreAllMocks()
    if (originalWebSocketPair === undefined) {
      delete (globalThis as any).WebSocketPair
    } else {
      ;(globalThis as any).WebSocketPair = originalWebSocketPair
    }
  })

  function createContext(user: any, upgradeHeader?: string): MockContext {
    return {
      get: (key: string) => (key === 'user' ? user : undefined),
      req: {
        header: (name: string) => (name === 'Upgrade' ? upgradeHeader : undefined),
      },
      json: (data: unknown, status = 200) =>
        new Response(JSON.stringify(data), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
    }
  }

  it('returns 401 when user is missing', async () => {
    const c = createContext(null)
    const response = await websocketHandler(c as any)

    expect(response.status).toBe(401)
    const body = await response.json() as { error: string }
    expect(body.error).toBe('Unauthorized')
  })

  it('returns 426 when upgrade header is missing', async () => {
    const c = createContext({ sub: 1 }, undefined)
    const response = await websocketHandler(c as any)

    expect(response.status).toBe(426)
    const body = await response.json() as { error: string }
    expect(body.error).toBe('Expected WebSocket upgrade')
  })

  it('accepts websocket and handles ping/unknown/subscribe/unsubscribe messages', async () => {
    const client = new FakeWebSocket()
    const server = new FakeWebSocket()

    ;(globalThis as any).WebSocketPair = vi.fn(() => [client, server])

    const c = createContext({ sub: 42 }, 'websocket')
    await expect(websocketHandler(c as any)).rejects.toThrow('init["status"] must be in the range of 200 to 599')

    const connected = JSON.parse(server.sent[0])
    expect(connected.type).toBe('connected')
    expect(connected.payload.userId).toBe(42)

    server.emit('message', { data: JSON.stringify({ type: 'ping' }) })
    expect(server.sent.some(m => JSON.parse(m).type === 'pong')).toBe(true)

    server.emit('message', { data: JSON.stringify({ type: 'subscribe', payload: 'nodes' }) })
    expect(server.sent.some(m => JSON.parse(m).type === 'subscribed')).toBe(true)

    server.emit('message', { data: JSON.stringify({ type: 'unsubscribe', payload: 'nodes' }) })
    expect(server.sent.some(m => JSON.parse(m).type === 'unsubscribed')).toBe(true)

    server.emit('message', { data: JSON.stringify({ type: 'invalid_type' }) })
    expect(server.sent.some(m => {
      const data = JSON.parse(m)
      return data.type === 'error' && String(data.payload).includes('Unknown message type')
    })).toBe(true)
  })

  it('returns error for invalid json message payload', async () => {
    const client = new FakeWebSocket()
    const server = new FakeWebSocket()

    ;(globalThis as any).WebSocketPair = vi.fn(() => [client, server])

    const c = createContext({ sub: 7 }, 'websocket')
    await expect(websocketHandler(c as any)).rejects.toThrow('init["status"] must be in the range of 200 to 599')

    server.emit('message', { data: '{not-json' })

    expect(server.sent.some(m => {
      const data = JSON.parse(m)
      return data.type === 'error' && data.payload === 'Invalid message format'
    })).toBe(true)
  })
})
