import { describe, expect, it } from 'vitest'
import app from '../src/index'
import { bootstrapPrincipals, createTestEnv } from './helpers/fixtures'

describe('internal developer mode', () => {
  it('hides developer endpoints when developer mode is disabled', async () => {
    const env = createTestEnv({ DEVELOPER_MODE: 'false' })
    const principals = await bootstrapPrincipals(env, 'dev-disabled')

    const res = await app.request('/api/v1/internal/dev/status', {
      headers: { Authorization: `Bearer ${principals.admin.token}` },
    }, env)

    expect(res.status).toBe(404)
  })

  it('exposes developer endpoints to admin jwt users when enabled', async () => {
    const env = createTestEnv({ DEVELOPER_MODE: 'true' })
    const principals = await bootstrapPrincipals(env, 'dev-enabled')

    const res = await app.request('/api/v1/internal/dev/status', {
      headers: { Authorization: `Bearer ${principals.admin.token}` },
    }, env)

    expect(res.status).toBe(200)
    const body = await res.json() as {
      success: boolean
      data: {
        developer_mode: boolean
        actor: { role: string; auth_method: string }
      }
    }

    expect(body.success).toBe(true)
    expect(body.data.developer_mode).toBe(true)
    expect(body.data.actor.role).toBe('admin')
    expect(body.data.actor.auth_method).toBe('jwt')
  })

  it('rejects non-admin users even when developer mode is enabled', async () => {
    const env = createTestEnv({ DEVELOPER_MODE: 'true' })
    const principals = await bootstrapPrincipals(env, 'dev-viewer')

    const res = await app.request('/api/v1/internal/dev/status', {
      headers: { Authorization: `Bearer ${principals.viewer.token}` },
    }, env)

    expect(res.status).toBe(403)
  })

  it('returns diagnostics and fixture catalog for admin jwt users', async () => {
    const env = createTestEnv({ DEVELOPER_MODE: 'true' })
    const principals = await bootstrapPrincipals(env, 'dev-catalog')

    const diagnosticsRes = await app.request('/api/v1/internal/dev/diagnostics', {
      headers: { Authorization: `Bearer ${principals.admin.token}` },
    }, env)
    const fixturesRes = await app.request('/api/v1/internal/dev/fixtures', {
      headers: { Authorization: `Bearer ${principals.admin.token}` },
    }, env)

    expect(diagnosticsRes.status).toBe(200)
    expect(fixturesRes.status).toBe(200)

    const diagnostics = await diagnosticsRes.json() as { data: { security: { admin_only: boolean; jwt_only: boolean } } }
    const fixtures = await fixturesRes.json() as { data: { fixtures: Array<{ key: string; status: string }> } }

    expect(diagnostics.data.security.admin_only).toBe(true)
    expect(diagnostics.data.security.jwt_only).toBe(true)
    expect(fixtures.data.fixtures.some(item => item.key === 'principals' && item.status === 'available')).toBe(true)
  })
})
