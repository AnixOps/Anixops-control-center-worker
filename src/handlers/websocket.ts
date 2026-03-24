/**
 * WebSocket Handler for Cloudflare Workers
 * 不使用 Durable Object 的简化实现
 */

import type { Context } from 'hono'
import type { Env } from '../types'

interface WebSocketClient {
  webSocket: WebSocket
  userId?: number
  channels: Set<string>
  connectedAt: Date
}

// 存储活跃的 WebSocket 连接
const clients = new Map<WebSocket, WebSocketClient>()

/**
 * WebSocket 升级处理
 */
export async function websocketHandler(c: Context<{ Bindings: Env }>) {
  // 验证用户身份
  const user = c.get('user')
  if (!user) {
    return c.json({ success: false, error: 'Unauthorized' }, 401)
  }

  // 检查是否是 WebSocket 升级请求
  const upgradeHeader = c.req.header('Upgrade')
  if (upgradeHeader !== 'websocket') {
    return c.json({ success: false, error: 'Expected WebSocket upgrade' }, 426)
  }

  // 创建 WebSocket Pair
  const pair = new WebSocketPair()
  const [client, server] = [pair[0], pair[1]]

  // 接受服务端 WebSocket
  server.accept()

  // 存储客户端信息
  const clientInfo: WebSocketClient = {
    webSocket: server,
    userId: user.sub,
    channels: new Set(['global', `user:${user.sub}`]),
    connectedAt: new Date(),
  }
  clients.set(server, clientInfo)

  // 发送连接成功消息
  server.send(JSON.stringify({
    type: 'connected',
    payload: {
      userId: user.sub,
      channels: Array.from(clientInfo.channels),
    },
    timestamp: new Date().toISOString(),
  }))

  // 设置心跳
  const heartbeatInterval = setInterval(() => {
    try {
      server.send(JSON.stringify({ type: 'ping' }))
    } catch {
      clearInterval(heartbeatInterval)
      clients.delete(server)
    }
  }, 30000)

  // 处理消息
  server.addEventListener('message', async (event) => {
    try {
      const data = JSON.parse(event.data as string)
      await handleWebSocketMessage(server, clientInfo, data)
    } catch (err) {
      server.send(JSON.stringify({ type: 'error', payload: 'Invalid message format' }))
    }
  })

  // 处理关闭
  server.addEventListener('close', () => {
    clearInterval(heartbeatInterval)
    clients.delete(server)
  })

  // 处理错误
  server.addEventListener('error', () => {
    clearInterval(heartbeatInterval)
    clients.delete(server)
  })

  // 返回 WebSocket 响应
  return new Response(null, {
    status: 101,
    webSocket: client,
  })
}

/**
 * 处理 WebSocket 消息
 */
async function handleWebSocketMessage(
  ws: WebSocket,
  client: WebSocketClient,
  data: { type: string; payload?: unknown }
) {
  switch (data.type) {
    case 'pong':
      // 心跳响应，忽略
      break

    case 'ping':
      ws.send(JSON.stringify({ type: 'pong' }))
      break

    case 'subscribe':
      if (data.payload && typeof data.payload === 'string') {
        client.channels.add(data.payload)
        ws.send(JSON.stringify({
          type: 'subscribed',
          payload: { channel: data.payload },
        }))
      }
      break

    case 'unsubscribe':
      if (data.payload && typeof data.payload === 'string') {
        client.channels.delete(data.payload)
        ws.send(JSON.stringify({
          type: 'unsubscribed',
          payload: { channel: data.payload },
        }))
      }
      break

    case 'broadcast':
      // 广播消息到指定频道
      if (data.payload && typeof data.payload === 'object') {
        const { channel, message } = data.payload as { channel: string; message: unknown }
        broadcastToChannel(channel, {
          type: 'message',
          payload: message,
          fromUserId: client.userId,
          timestamp: new Date().toISOString(),
        })
      }
      break

    default:
      ws.send(JSON.stringify({ type: 'error', payload: `Unknown message type: ${data.type}` }))
  }
}

/**
 * 向特定频道广播消息
 */
export function broadcastToChannel(channel: string, message: unknown): void {
  const messageStr = JSON.stringify(message)

  for (const [ws, client] of clients) {
    if (client.channels.has(channel)) {
      try {
        ws.send(messageStr)
      } catch {
        clients.delete(ws)
      }
    }
  }
}

/**
 * 向特定用户发送消息
 */
export function sendToUser(userId: number, message: unknown): void {
  const channel = `user:${userId}`
  broadcastToChannel(channel, message)
}

/**
 * 广播节点状态更新
 */
export function broadcastNodeUpdate(nodeId: number, status: string, data?: Record<string, unknown>): void {
  const message = {
    type: 'node_update',
    payload: {
      nodeId,
      status,
      ...data,
    },
    timestamp: new Date().toISOString(),
  }

  broadcastToChannel('nodes', message)
  broadcastToChannel(`node:${nodeId}`, message)
}

/**
 * 广播任务状态更新
 */
export function broadcastTaskUpdate(taskId: string, status: string, data?: Record<string, unknown>): void {
  const message = {
    type: 'task_update',
    payload: {
      taskId,
      status,
      ...data,
    },
    timestamp: new Date().toISOString(),
  }

  broadcastToChannel('tasks', message)
  broadcastToChannel(`task:${taskId}`, message)
}

/**
 * 广播日志消息
 */
export function broadcastLog(taskId: string, log: { level: string; message: string; node?: string }): void {
  const message = {
    type: 'log',
    payload: {
      taskId,
      ...log,
    },
    timestamp: new Date().toISOString(),
  }

  broadcastToChannel('logs', message)
  broadcastToChannel(`task:${taskId}`, message)
}

/**
 * 获取连接统计
 */
export function getWebSocketStats(): { totalConnections: number; channels: string[] } {
  const allChannels = new Set<string>()
  for (const client of clients.values()) {
    for (const channel of client.channels) {
      allChannels.add(channel)
    }
  }

  return {
    totalConnections: clients.size,
    channels: Array.from(allChannels),
  }
}