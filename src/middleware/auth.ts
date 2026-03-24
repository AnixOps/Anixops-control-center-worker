import type { Context, Next } from 'hono'
import { jwtVerify } from 'jose'
import type { Env } from '../types'
import { isTokenRevoked, isUserSessionRevoked } from '../utils/token'

// Internal JWT Payload type
interface AppJWTPayload {
  sub: number
  email: string
  role: string
  iat: number
  exp: number
}

/**
 * 检查 Token 是否在黑名单中
 */
async function isTokenBlacklisted(kv: KVNamespace, token: string): Promise<boolean> {
  return isTokenRevoked(kv, token)
}

/**
 * JWT 认证中间件
 */
export async function authMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  const authHeader = c.req.header('Authorization')

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ success: false, error: 'Unauthorized: Missing or invalid Authorization header' }, 401)
  }

  const token = authHeader.substring(7)

  try {
    // 检查 Token 黑名单
    if (await isTokenBlacklisted(c.env.KV, token)) {
      return c.json({ success: false, error: 'Token has been revoked' }, 401)
    }

    const secret = new TextEncoder().encode(c.env.JWT_SECRET)
    const { payload } = await jwtVerify(token, secret)

    // Convert jose JWTPayload to our internal format
    const userPayload: AppJWTPayload = {
      sub: typeof payload.sub === 'string' ? parseInt(payload.sub, 10) : (typeof payload.sub === 'number' ? payload.sub : 0),
      email: payload.email as string,
      role: payload.role as string,
      iat: payload.iat || 0,
      exp: payload.exp || 0,
    }

    // 检查用户会话是否被全局撤销
    if (await isUserSessionRevoked(c.env.KV, userPayload.sub, userPayload.iat)) {
      return c.json({ success: false, error: 'Session has been revoked. Please login again.' }, 401)
    }

    c.set('user', userPayload as unknown as import('../types').JWTPayload)
    await next()
  } catch (err) {
    if (err instanceof Error) {
      if (err.message.includes('expired')) {
        return c.json({ success: false, error: 'Token expired' }, 401)
      }
    }
    return c.json({ success: false, error: 'Invalid token' }, 401)
  }
}

/**
 * 基于角色的访问控制中间件
 */
export function rbacMiddleware(allowedRoles: string[]) {
  return async (c: Context<{ Bindings: Env }>, next: Next) => {
    const user = c.get('user')

    if (!user) {
      return c.json({ success: false, error: 'Unauthorized' }, 401)
    }

    if (!allowedRoles.includes(user.role)) {
      return c.json({
        success: false,
        error: 'Forbidden: Insufficient permissions',
        required_roles: allowedRoles,
        your_role: user.role,
      }, 403)
    }

    await next()
  }
}

/**
 * API Key 认证中间件 (用于代理/CLI)
 */
export async function apiKeyMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  const apiKey = c.req.header('X-API-Key')

  if (!apiKey) {
    return c.json({ success: false, error: 'Missing API Key' }, 401)
  }

  // 验证 API Key
  const result = await c.env.DB
    .prepare(`
      SELECT u.id, u.email, u.role
      FROM api_tokens t
      JOIN users u ON t.user_id = u.id
      WHERE t.token = ? AND (t.expires_at IS NULL OR t.expires_at > datetime('now'))
    `)
    .bind(apiKey)
    .first<{ id: number; email: string; role: string }>()

  if (!result) {
    return c.json({ success: false, error: 'Invalid or expired API Key' }, 401)
  }

  // 更新最后使用时间
  await c.env.DB
    .prepare('UPDATE api_tokens SET last_used = datetime(\'now\') WHERE token = ?')
    .bind(apiKey)
    .run()

  c.set('user', {
    sub: result.id,
    email: result.email,
    role: result.role,
    iat: Date.now() / 1000,
    exp: 0,
  })

  await next()
}