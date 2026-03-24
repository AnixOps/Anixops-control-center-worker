/**
 * Prometheus Metrics Handler
 *
 * Exposes metrics in Prometheus format for monitoring
 */

import type { Context } from 'hono'
import type { Env } from '../types'

interface MetricValue {
  name: string
  help: string
  type: 'counter' | 'gauge' | 'histogram'
  value: number
  labels?: Record<string, string>
}

/**
 * Format metric for Prometheus exposition format
 */
function formatMetric(metric: MetricValue): string {
  const lines: string[] = []

  // Help line
  lines.push(`# HELP ${metric.name} ${metric.help}`)

  // Type line
  lines.push(`# TYPE ${metric.name} ${metric.type}`)

  // Value line with labels
  if (metric.labels && Object.keys(metric.labels).length > 0) {
    const labelStr = Object.entries(metric.labels)
      .map(([k, v]) => `${k}="${v}"`)
      .join(',')
    lines.push(`${metric.name}{${labelStr}} ${metric.value}`)
  } else {
    lines.push(`${metric.name} ${metric.value}`)
  }

  return lines.join('\n')
}

/**
 * Collect system metrics
 */
async function collectMetrics(env: Env): Promise<MetricValue[]> {
  const metrics: MetricValue[] = []

  // Database metrics
  const userCount = await env.DB
    .prepare('SELECT COUNT(*) as count FROM users')
    .first<{ count: number }>()

  const nodeCount = await env.DB
    .prepare('SELECT COUNT(*) as count FROM nodes')
    .first<{ count: number }>()

  const taskCount = await env.DB
    .prepare('SELECT COUNT(*) as count FROM tasks')
    .first<{ count: number }>()

  const playbookCount = await env.DB
    .prepare('SELECT COUNT(*) as count FROM playbooks')
    .first<{ count: number }>()

  // Node status breakdown
  const nodeStatus = await env.DB
    .prepare('SELECT status, COUNT(*) as count FROM nodes GROUP BY status')
    .all<{ status: string; count: number }>()

  // Task status breakdown
  const taskStatus = await env.DB
    .prepare('SELECT status, COUNT(*) as count FROM tasks GROUP BY status')
    .all<{ status: string; count: number }>()

  // Basic counts
  metrics.push({
    name: 'anixops_users_total',
    help: 'Total number of users',
    type: 'gauge',
    value: userCount?.count || 0,
  })

  metrics.push({
    name: 'anixops_nodes_total',
    help: 'Total number of nodes',
    type: 'gauge',
    value: nodeCount?.count || 0,
  })

  metrics.push({
    name: 'anixops_tasks_total',
    help: 'Total number of tasks',
    type: 'gauge',
    value: taskCount?.count || 0,
  })

  metrics.push({
    name: 'anixops_playbooks_total',
    help: 'Total number of playbooks',
    type: 'gauge',
    value: playbookCount?.count || 0,
  })

  // Node status metrics
  for (const row of nodeStatus.results) {
    metrics.push({
      name: 'anixops_nodes_by_status',
      help: 'Number of nodes by status',
      type: 'gauge',
      value: row.count,
      labels: { status: row.status },
    })
  }

  // Task status metrics
  for (const row of taskStatus.results) {
    metrics.push({
      name: 'anixops_tasks_by_status',
      help: 'Number of tasks by status',
      type: 'gauge',
      value: row.count,
      labels: { status: row.status },
    })
  }

  // System info
  metrics.push({
    name: 'anixops_info',
    help: 'AnixOps system information',
    type: 'gauge',
    value: 1,
    labels: {
      version: '1.0.0',
      phase: '4',
    },
  })

  // Uptime (placeholder)
  metrics.push({
    name: 'anixops_uptime_seconds',
    help: 'System uptime in seconds',
    type: 'gauge',
    value: 0,
  })

  return metrics
}

/**
 * Prometheus metrics endpoint handler
 */
export async function prometheusMetricsHandler(c: Context<{ Bindings: Env }>) {
  try {
    const metrics = await collectMetrics(c.env)
    const output = metrics.map(formatMetric).join('\n')

    return c.text(output + '\n', 200, {
      'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
      'Cache-Control': 'no-cache',
    })
  } catch (err) {
    console.error('Metrics collection error:', err)
    return c.text('# Error collecting metrics\n', 500, {
      'Content-Type': 'text/plain; version=0.0.4',
    })
  }
}

/**
 * Health check with detailed status
 */
export async function detailedHealthHandler(c: Context<{ Bindings: Env }>) {
  const checks: Record<string, { status: string; latency?: number; error?: string }> = {}

  // Check database
  const dbStart = Date.now()
  try {
    await c.env.DB.prepare('SELECT 1').first()
    checks.database = {
      status: 'healthy',
      latency: Date.now() - dbStart,
    }
  } catch (err) {
    checks.database = {
      status: 'unhealthy',
      error: err instanceof Error ? err.message : 'Unknown error',
    }
  }

  // Check KV
  const kvStart = Date.now()
  try {
    await c.env.KV.put('health:check', 'ok', { expirationTtl: 60 })
    const value = await c.env.KV.get('health:check')
    checks.kv = {
      status: value === 'ok' ? 'healthy' : 'unhealthy',
      latency: Date.now() - kvStart,
    }
  } catch (err) {
    checks.kv = {
      status: 'unhealthy',
      error: err instanceof Error ? err.message : 'Unknown error',
    }
  }

  // Check R2
  const r2Start = Date.now()
  try {
    await c.env.R2.put('health/check', 'ok')
    checks.r2 = {
      status: 'healthy',
      latency: Date.now() - r2Start,
    }
  } catch (err) {
    checks.r2 = {
      status: 'unhealthy',
      error: err instanceof Error ? err.message : 'Unknown error',
    }
  }

  // Overall status
  const allHealthy = Object.values(checks).every(c => c.status === 'healthy')

  return c.json({
    status: allHealthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    version: '1.0.0-rc.17',
    checks,
  }, allHealthy ? 200 : 503)
}

/**
 * Readiness probe for Kubernetes
 */
export async function readinessHandler(c: Context<{ Bindings: Env }>) {
  try {
    // Quick check that essential services are available
    await c.env.DB.prepare('SELECT 1').first()
    return c.text('OK', 200)
  } catch (err) {
    return c.text('Not Ready', 503)
  }
}

/**
 * Liveness probe for Kubernetes
 */
export async function livenessHandler(c: Context<{ Bindings: Env }>) {
  return c.text('OK', 200)
}