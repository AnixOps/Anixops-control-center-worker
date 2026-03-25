import type { Context } from 'hono'
import type { AuthPrincipal, Env } from '../types'
import { getRequestId, logAudit } from '../utils/audit'

function isDeveloperModeEnabled(env: Env): boolean {
  return env.DEVELOPER_MODE === 'true'
}

function getPrincipal(c: Context<{ Bindings: Env }>): AuthPrincipal {
  return c.get('user') as AuthPrincipal
}

function notFound(c: Context<{ Bindings: Env }>) {
  return c.json({ success: false, error: 'Not Found' }, 404)
}

async function ensureDeveloperAccess(c: Context<{ Bindings: Env }>) {
  if (!isDeveloperModeEnabled(c.env)) {
    return notFound(c)
  }

  const principal = getPrincipal(c)
  if (principal.auth_method !== 'jwt') {
    return c.json({ success: false, error: 'Developer mode requires JWT authentication' }, 403)
  }

  return null
}

export async function developerModeStatusHandler(c: Context<{ Bindings: Env }>) {
  const denied = await ensureDeveloperAccess(c)
  if (denied) return denied

  const principal = getPrincipal(c)
  await logAudit(c, principal.sub, 'view_developer_mode_status', 'internal_debug', {
    auth_method: principal.auth_method,
    role: principal.role,
  })

  return c.json({
    success: true,
    data: {
      developer_mode: true,
      environment: c.env.ENVIRONMENT,
      version: c.env.APP_VERSION || '1.0.0',
      build_sha: c.env.BUILD_SHA || 'unknown',
      request_id: getRequestId(c),
      actor: {
        id: principal.sub,
        email: principal.email,
        role: principal.role,
        auth_method: principal.auth_method,
      },
      capabilities: ['diagnostics.read', 'fixtures.catalog.read', 'developer_mode.audit'],
    },
  })
}

export async function developerDiagnosticsHandler(c: Context<{ Bindings: Env }>) {
  const denied = await ensureDeveloperAccess(c)
  if (denied) return denied

  const principal = getPrincipal(c)
  await logAudit(c, principal.sub, 'view_developer_diagnostics', 'internal_debug', {
    auth_method: principal.auth_method,
    role: principal.role,
  })

  return c.json({
    success: true,
    data: {
      runtime: {
        environment: c.env.ENVIRONMENT,
        developer_mode: true,
        version: c.env.APP_VERSION || '1.0.0',
        build_sha: c.env.BUILD_SHA || 'unknown',
        has_analytics: Boolean(c.env.ANALYTICS),
        has_vectorize: Boolean(c.env.VECTORIZE),
        has_kubernetes_api: Boolean(c.env.KUBERNETES_API_SERVER),
      },
      routing: {
        public_health_endpoints: ['/health', '/health/detailed', '/readiness', '/liveness', '/metrics'],
        internal_debug_endpoints: [
          '/api/v1/internal/dev/status',
          '/api/v1/internal/dev/diagnostics',
          '/api/v1/internal/dev/fixtures',
        ],
      },
      security: {
        admin_only: true,
        jwt_only: true,
        audited: true,
        hides_when_disabled: true,
      },
    },
  })
}

export async function developerFixturesCatalogHandler(c: Context<{ Bindings: Env }>) {
  const denied = await ensureDeveloperAccess(c)
  if (denied) return denied

  const principal = getPrincipal(c)
  await logAudit(c, principal.sub, 'view_developer_fixture_catalog', 'internal_debug', {
    auth_method: principal.auth_method,
    role: principal.role,
  })

  return c.json({
    success: true,
    data: {
      fixtures: [
        {
          key: 'principals',
          status: 'available',
          description: 'Deterministic admin/operator/viewer bootstrap for automated and manual testing.',
        },
        {
          key: 'incidents',
          status: 'planned',
          description: 'Reusable seeded incident records for dashboard, analytics, and workflow testing.',
        },
        {
          key: 'nodes',
          status: 'planned',
          description: 'Reusable seeded node and infrastructure records for operations testing.',
        },
      ],
      notes: [
        'This endpoint is descriptive only; it does not mutate runtime state.',
        'Fixture creation remains test-harness driven until explicit runtime seeding is implemented.',
      ],
    },
  })
}
