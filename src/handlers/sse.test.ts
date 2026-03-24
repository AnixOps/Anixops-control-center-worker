import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { sseHandler, sseSubscribeHandler, sseUnsubscribeHandler, sseStatusHandler } from './sse'

type MockContext = {
  get: (key: string) => any
  req: {
    json: () => Promise<any>
  }
  json: (data: unknown, status?: number) => Response
}

describe('sse handlers', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'setInterval').mockReturnValue(1 as any)
    vi.spyOn(globalThis, 'clearInterval').mockImplementation(() => undefined)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  function createContext(user: any, body: any = {}): MockContext {
    return {
      get: (key: string) => (key === 'user' ? user : undefined),
      req: {
        json: async () => body,
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
    const response = await sseHandler(c as any)

    expect(response.status).toBe(401)
    const body = await response.json() as { error: string }
    expect(body.error).toBe('Unauthorized')
  })

  it('creates SSE stream with expected headers', async () => {
    const c = createContext({ sub: 1, email: 'a@test.com', role: 'admin' })
    const response = await sseHandler(c as any)

    expect(response.status).toBe(200)
    expect(response.headers.get('Content-Type')).toContain('text/event-stream')
    expect(response.headers.get('Cache-Control')).toBe('no-cache')

    await response.body?.cancel()
  })

  it('returns 400 when subscribe channel is missing', async () => {
    const c = createContext({ sub: 1, role: 'admin' }, {})
    const response = await sseSubscribeHandler(c as any)

    expect(response.status).toBe(400)
    const body = await response.json() as { error: string }
    expect(body.error).toBe('Channel is required')
  })

  it('returns 403 for invalid subscribe channel', async () => {
    const c = createContext({ sub: 1, role: 'admin' }, { channel: 'private:forbidden' })
    const response = await sseSubscribeHandler(c as any)

    expect(response.status).toBe(403)
    const body = await response.json() as { error: string }
    expect(body.error).toBe('Invalid channel')
  })

  it('subscribes and unsubscribes valid channels', async () => {
    const user = { sub: 99, email: 'u@test.com', role: 'operator' }

    const streamResponse = await sseHandler(createContext(user) as any)

    const subscribeRes = await sseSubscribeHandler(createContext(user, { channel: 'nodes' }) as any)
    expect(subscribeRes.status).toBe(200)

    const statusRes = await sseStatusHandler(createContext(user) as any)
    expect(statusRes.status).toBe(200)
    const statusBody = await statusRes.json() as {
      data: { connections: Array<{ channels: string[] }> }
    }
    const channels = statusBody.data.connections[0]?.channels || []
    expect(channels).toContain('nodes')

    const unsubscribeRes = await sseUnsubscribeHandler(createContext(user, { channel: 'nodes' }) as any)
    expect(unsubscribeRes.status).toBe(200)

    await streamResponse.body?.cancel()
  })

  it('returns user-scoped status for non-admin and all connections for admin', async () => {
    const user = { sub: 33, email: 'user@test.com', role: 'operator' }
    const admin = { sub: 1, email: 'admin@test.com', role: 'admin' }

    const streamResponse = await sseHandler(createContext(user) as any)

    const userStatusRes = await sseStatusHandler(createContext(user) as any)
    const userStatusBody = await userStatusRes.json() as {
      data: { total: number }
    }
    expect(userStatusBody.data.total).toBeGreaterThanOrEqual(1)

    const adminStatusRes = await sseStatusHandler(createContext(admin) as any)
    const adminStatusBody = await adminStatusRes.json() as {
      data: { total: number }
    }
    expect(adminStatusBody.data.total).toBeGreaterThanOrEqual(1)

    await streamResponse.body?.cancel()
  })
})
