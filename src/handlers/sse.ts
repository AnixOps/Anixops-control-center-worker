/**
 * Server-Sent Events (SSE) Handler
 * 替代 WebSocket 实现实时通信
 */

import type { Context } from 'hono'
import type { Env } from '../types'

interface SSEMessage {
  type: string
  payload: unknown
  timestamp: string
}

interface SSEClient {
  id: string
  userId: number
  email: string
  role: string
  channels: Set<string>
  connectedAt: string
}

// 存储活跃的 SSE 连接
const clients = new Map<string, { controller: ReadableStreamDefaultController; client: SSEClient }>()

/**
 * 格式化 SSE 消息
 */
function formatSSEMessage(message: SSEMessage): string {
  return `data: ${JSON.stringify(message)}\n\n`
}

/**
 * 发送心跳消息
 */
function formatHeartbeat(): string {
  return ': heartbeat\n\n'
}

/**
 * SSE 连接处理
 */
export async function sseHandler(c: Context<{ Bindings: Env }>) {
  const user = c.get('user')

  if (!user) {
    return c.json({ success: false, error: 'Unauthorized' }, 401)
  }

  const clientId = `${user.sub}-${Date.now()}`
  const client: SSEClient = {
    id: clientId,
    userId: user.sub,
    email: user.email,
    role: user.role,
    channels: new Set(['global', `user:${user.sub}`]),
    connectedAt: new Date().toISOString(),
  }

  // 创建可读流
  const stream = new ReadableStream({
    start(controller) {
      // 存储连接
      clients.set(clientId, { controller, client })

      // 发送初始连接消息
      const initMessage: SSEMessage = {
        type: 'connected',
        payload: {
          client_id: clientId,
          user_id: user.sub,
          channels: Array.from(client.channels),
        },
        timestamp: new Date().toISOString(),
      }
      controller.enqueue(new TextEncoder().encode(formatSSEMessage(initMessage)))

      // 设置心跳定时器
      const heartbeatInterval = setInterval(() => {
        try {
          controller.enqueue(new TextEncoder().encode(formatHeartbeat()))
        } catch {
          clearInterval(heartbeatInterval)
        }
      }, 30000) // 30秒心跳

      // 存储心跳定时器以便清理
      const controllerWithInterval = controller as ReadableStreamDefaultController & { _heartbeatInterval?: ReturnType<typeof setInterval> }
      controllerWithInterval._heartbeatInterval = heartbeatInterval
    },

    cancel() {
      // 清理连接
      const clientData = clients.get(clientId)
      if (clientData) {
        const controllerWithInterval = clientData.controller as ReadableStreamDefaultController & { _heartbeatInterval?: ReturnType<typeof setInterval> }
        if (controllerWithInterval._heartbeatInterval) {
          clearInterval(controllerWithInterval._heartbeatInterval)
        }
      }
      clients.delete(clientId)
    },
  })

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no', // 禁用 Nginx 缓冲
    },
  })
}

/**
 * SSE 订阅频道
 */
export async function sseSubscribeHandler(c: Context<{ Bindings: Env }>) {
  const user = c.get('user')
  const body = await c.req.json<{ channel?: string }>()
  const channel = body.channel

  if (!channel) {
    return c.json({ success: false, error: 'Channel is required' }, 400)
  }

  // 权限检查
  const allowedChannels = ['global', 'nodes', 'tasks', 'logs', `user:${user.sub}`]
  if (!allowedChannels.includes(channel) && !channel.startsWith('node:') && !channel.startsWith('task:')) {
    return c.json({ success: false, error: 'Invalid channel' }, 403)
  }

  // 更新所有相关连接的频道订阅
  for (const [clientId, data] of clients) {
    if (data.client.userId === user.sub) {
      data.client.channels.add(channel)
    }
  }

  return c.json({
    success: true,
    message: `Subscribed to channel: ${channel}`,
  })
}

/**
 * SSE 取消订阅频道
 */
export async function sseUnsubscribeHandler(c: Context<{ Bindings: Env }>) {
  const user = c.get('user')
  const body = await c.req.json<{ channel?: string }>()
  const channel = body.channel

  if (!channel) {
    return c.json({ success: false, error: 'Channel is required' }, 400)
  }

  // 更新所有相关连接的频道订阅
  for (const [clientId, data] of clients) {
    if (data.client.userId === user.sub) {
      data.client.channels.delete(channel)
    }
  }

  return c.json({
    success: true,
    message: `Unsubscribed from channel: ${channel}`,
  })
}

/**
 * 获取 SSE 连接状态
 */
export async function sseStatusHandler(c: Context<{ Bindings: Env }>) {
  const user = c.get('user')

  // 只允许管理员查看所有连接
  if (user.role !== 'admin') {
    const userConnections = Array.from(clients.values())
      .filter(data => data.client.userId === user.sub)
      .map(data => ({
        id: data.client.id,
        channels: Array.from(data.client.channels),
        connected_at: data.client.connectedAt,
      }))

    return c.json({
      success: true,
      data: {
        connections: userConnections,
        total: userConnections.length,
      },
    })
  }

  // 管理员可以看到所有连接
  const allConnections = Array.from(clients.values()).map(data => ({
    id: data.client.id,
    user_id: data.client.userId,
    email: data.client.email,
    channels: Array.from(data.client.channels),
    connected_at: data.client.connectedAt,
  }))

  return c.json({
    success: true,
    data: {
      connections: allConnections,
      total: allConnections.length,
    },
  })
}

/**
 * 向特定频道广播消息
 */
export function broadcastToChannel(channel: string, message: SSEMessage): void {
  const formattedMessage = formatSSEMessage(message)

  for (const data of clients.values()) {
    if (data.client.channels.has(channel)) {
      try {
        data.controller.enqueue(new TextEncoder().encode(formattedMessage))
      } catch {
        // 连接可能已关闭
      }
    }
  }
}

/**
 * 向特定用户发送消息
 */
export function sendToUser(userId: number, message: SSEMessage): void {
  const channel = `user:${userId}`
  broadcastToChannel(channel, message)
}

/**
 * 广播节点状态更新
 */
export function broadcastNodeUpdate(nodeId: number, status: string, data?: Record<string, unknown>): void {
  const message: SSEMessage = {
    type: 'node_update',
    payload: {
      node_id: nodeId,
      status,
      ...(data || {}),
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
  const message: SSEMessage = {
    type: 'task_update',
    payload: {
      task_id: taskId,
      status,
      ...(data || {}),
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
  const message: SSEMessage = {
    type: 'log',
    payload: {
      task_id: taskId,
      ...log,
    },
    timestamp: new Date().toISOString(),
  }

  broadcastToChannel('logs', message)
  broadcastToChannel(`task:${taskId}`, message)
}

/**
 * 发送通知
 */
export function sendNotification(userId: number, notification: { type: string; title: string; message: string }): void {
  const sseMessage: SSEMessage = {
    type: 'notification',
    payload: notification,
    timestamp: new Date().toISOString(),
  }

  sendToUser(userId, sseMessage)
}