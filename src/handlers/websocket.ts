/**
 * WebSocket handler for Cloudflare Workers
 * Unified realtime transport adapter
 */

import type { Context } from 'hono'
import type { Env } from '../types'
import {
  buildDefaultChannels,
  createRealtimeEvent,
  getRealtimeConnectionSnapshot,
  getRealtimeStats,
  isAllowedRealtimeChannel,
  registerRealtimeClient,
  resetRealtimeState,
  serializeWebSocketEvent,
  unregisterRealtimeClient,
  updateRealtimeUserChannel,
} from '../services/realtime'

/**
 * WebSocket upgrade handler
 */
export async function websocketHandler(c: Context<{ Bindings: Env }>) {
  const user = c.get('user')
  if (!user) {
    return c.json({ success: false, error: 'Unauthorized' }, 401)
  }

  const upgradeHeader = c.req.header('Upgrade')
  if (upgradeHeader?.toLowerCase() !== 'websocket') {
    return c.json({ success: false, error: 'Expected WebSocket upgrade' }, 426)
  }

  const tenant = c.get('tenant') as { id: number } | undefined
  const channels = buildDefaultChannels(user, tenant?.id)
  const pair = new WebSocketPair()
  const [client, server] = [pair[0], pair[1]]
  const clientId = crypto.randomUUID()

  server.accept()

  registerRealtimeClient({
    id: clientId,
    userId: user.sub,
    email: user.email,
    role: user.role,
    tenantId: tenant?.id,
    transport: 'websocket',
    channels,
    send: (message) => {
      try {
        server.send(message)
      } catch {
        unregisterRealtimeClient(clientId)
      }
    },
  })

  server.send(serializeWebSocketEvent(createRealtimeEvent({
    type: 'connected',
    scope: 'system',
    channels,
    user_id: user.sub,
    tenant_id: tenant?.id,
    payload: {
      client_id: clientId,
      user_id: user.sub,
      email: user.email,
      role: user.role,
      channels,
    },
  })))

  let heartbeatInterval: number | null = null
  try {
    heartbeatInterval = setInterval(() => {
      try {
        server.send(JSON.stringify({ type: 'ping' }))
      } catch {
        if (heartbeatInterval) {
          clearInterval(heartbeatInterval)
        }
      }
    }, 30000) as unknown as number
  } catch {
    // ignore interval setup failures
  }

  server.addEventListener('message', (event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data as string) as { type: string; payload?: unknown }
      handleWebSocketMessage(server, clientId, user.sub, data, tenant?.id)
    } catch {
      server.send(JSON.stringify({ type: 'error', payload: 'Invalid message format' }))
    }
  })

  const cleanup = () => {
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval)
    }
    unregisterRealtimeClient(clientId)
  }

  server.addEventListener('close', cleanup)
  server.addEventListener('error', cleanup)

  return new Response(null, {
    status: 101,
    webSocket: client,
  })
}

function handleWebSocketMessage(
  ws: WebSocket,
  clientId: string,
  userId: number,
  data: { type: string; payload?: unknown },
  tenantId?: number
) {
  switch (data.type) {
    case 'pong':
      break

    case 'ping':
      ws.send(JSON.stringify({ type: 'pong' }))
      break

    case 'subscribe': {
      if (typeof data.payload !== 'string') {
        ws.send(JSON.stringify({ type: 'error', payload: 'Invalid subscription payload' }))
        break
      }

      const channel = data.payload.trim()
      if (!isAllowedRealtimeChannel({ sub: userId, role: 'viewer' }, channel, tenantId)) {
        ws.send(JSON.stringify({ type: 'error', payload: `Invalid channel: ${channel}` }))
        break
      }

      const changed = updateRealtimeUserChannel(userId, channel, 'subscribe')
      ws.send(JSON.stringify({
        type: 'subscribed',
        payload: {
          channel,
          changed,
        },
      }))
      break
    }

    case 'unsubscribe': {
      if (typeof data.payload !== 'string') {
        ws.send(JSON.stringify({ type: 'error', payload: 'Invalid subscription payload' }))
        break
      }

      const channel = data.payload.trim()
      const changed = updateRealtimeUserChannel(userId, channel, 'unsubscribe')
      ws.send(JSON.stringify({
        type: 'unsubscribed',
        payload: {
          channel,
          changed,
        },
      }))
      break
    }

    case 'broadcast': {
      if (data.payload && typeof data.payload === 'object') {
        ws.send(JSON.stringify({
          type: 'message',
          payload: {
            ...data.payload as Record<string, unknown>,
            fromUserId: userId,
            clientId,
          },
          timestamp: new Date().toISOString(),
        }))
      }
      break
    }

    default:
      ws.send(JSON.stringify({ type: 'error', payload: `Unknown message type: ${data.type}` }))
  }
}

/**
 * WebSocket status endpoint helper
 */
export function getWebSocketStats(): { status: string; data: ReturnType<typeof getRealtimeStats>; connections: ReturnType<typeof getRealtimeConnectionSnapshot> } {
  return {
    status: 'live',
    data: getRealtimeStats(),
    connections: getRealtimeConnectionSnapshot(),
  }
}

export { resetRealtimeState }
