import type { Context } from 'hono'
import type { Env } from '../types'

/**
 * 健康检查
 */
export async function healthHandler(c: Context<{ Bindings: Env }>) {
  return c.json({
    status: 'healthy',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: c.env.ENVIRONMENT,
  })
}

/**
 * 就绪检查
 */
export async function readinessHandler(c: Context<{ Bindings: Env }>) {
  const checks: Record<string, boolean> = {}

  // 检查 D1 数据库
  try {
    await c.env.DB.prepare('SELECT 1').first()
    checks.database = true
  } catch {
    checks.database = false
  }

  // 检查 KV
  try {
    await c.env.KV.get('health:check')
    checks.kv = true
  } catch {
    checks.kv = false
  }

  // 检查 R2
  try {
    await c.env.R2.head('health:check')
    checks.r2 = true
  } catch {
    checks.r2 = false
  }

  const allHealthy = Object.values(checks).every(Boolean)

  return c.json({
    status: allHealthy ? 'ready' : 'degraded',
    checks,
    timestamp: new Date().toISOString(),
  }, allHealthy ? 200 : 503)
}