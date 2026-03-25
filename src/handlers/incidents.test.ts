import { describe, it, expect } from 'vitest'
import app from '../index'
import type { Env } from '../types'
import { createMockD1, createMockKV, createMockR2 } from '../../test/setup'

function createEnv(): Env {
  return {
    ENVIRONMENT: 'development',
    JWT_SECRET: 'incident-test-secret-key-min-32-characters!',
    JWT_EXPIRE: '3600',
    API_KEY_SALT: 'incident-test-salt',
    DB: createMockD1(),
    KV: createMockKV(),
    R2: createMockR2(),
    AI: {
      run: async () => ({
        response: JSON.stringify({
          summary: 'Investigated incident',
          severity: 'medium',
          likely_cause: 'Synthetic test condition',
          recommended_actions: ['Review bounded remediation'],
        }),
      }),
    } as Env['AI'],
  }
}

async function registerAndLogin(env: Env, email: string, password: string, role: 'admin' | 'operator' | 'viewer' = 'admin') {
  await app.request('/api/v1/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, role }),
  }, env)

  const loginRes = await app.request('/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  }, env)

  const loginData = await loginRes.json() as { data?: { access_token: string } }
  return loginData.data?.access_token || ''
}

describe('incident handlers', () => {
  it('creates and executes a restart_deployment incident', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'incident-restart@example.com', 'IncidentRestart123!', 'admin')

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Restart deployment incident',
        source: 'test-suite',
        severity: 'high',
        action_type: 'restart_deployment',
        action_ref: 'default/anixops-api',
        evidence: [{ type: 'manual', source: 'test', content: 'Restart deployment' }],
      }),
    }, env)

    const createData = await createRes.json() as { data?: { id: string } }

    await app.request(`/api/v1/incidents/${createData.data?.id}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    const executeRes = await app.request(`/api/v1/incidents/${createData.data?.id}/execute`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(executeRes.status).toBe(200)
    const executeData = await executeRes.json() as { success: boolean; data?: { status: string; execution_result?: { restarted?: boolean } } }
    expect(executeData.success).toBe(true)
    expect(executeData.data?.status).toBe('resolved')
    expect(executeData.data?.execution_result?.success).toBe(true)
    expect(executeData.data?.execution_result?.backend).toBe('kubernetes')
  })

  it('automatically enriches evidence for restart_deployment incidents', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'incident-evidence@example.com', 'IncidentEvidence123!', 'admin')

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Evidence enrichment incident',
        source: 'test-suite',
        severity: 'medium',
        action_type: 'restart_deployment',
        action_ref: 'default/anixops-api',
        evidence: [{ type: 'manual', source: 'test', content: 'Manual evidence' }],
      }),
    }, env)

    expect(createRes.status).toBe(201)
    const createData = await createRes.json() as { data?: { evidence?: Array<{ source: string }> } }
    const evidence = createData.data?.evidence || []

    expect(evidence.length).toBeGreaterThan(1)
    expect(evidence.some(item => item.source === 'kubernetes.deployment')).toBe(true)
  })

  it('automatically enriches evidence for task references', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'incident-task-evidence@example.com', 'IncidentTaskEvidence123!', 'admin')

    await env.DB
      .prepare(`
        INSERT INTO tasks (task_id, playbook_id, playbook_name, status, trigger_type, triggered_by, target_nodes, variables)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind('task-evidence-1', 1, 'deploy-app', 'failed', 'manual', 1, '[]', '{}')
      .run()

    await env.DB
      .prepare(`
        INSERT INTO task_logs (task_id, node_id, node_name, level, message, metadata)
        VALUES (?, ?, ?, ?, ?, ?)
      `)
      .bind('task-evidence-1', null, 'node-a', 'error', 'Deployment failed', JSON.stringify({ reason: 'timeout' }))
      .run()

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Task evidence incident',
        source: 'task',
        severity: 'medium',
        action_ref: 'task:task-evidence-1',
      }),
    }, env)

    expect(createRes.status).toBe(201)
    const createData = await createRes.json() as { data?: { evidence?: Array<{ source: string }> } }
    const evidence = createData.data?.evidence || []
    expect(evidence.some(item => item.source === 'tasks.record')).toBe(true)
    expect(evidence.some(item => item.source === 'tasks.log')).toBe(true)
  })

  it('automatically enriches evidence for node references', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'incident-node-evidence@example.com', 'IncidentNodeEvidence123!', 'admin')

    const node = await env.DB
      .prepare(`
        INSERT INTO nodes (name, host, port, status, config)
        VALUES (?, ?, ?, 'offline', ?)
        RETURNING *
      `)
      .bind('node-evidence', '10.0.0.10', 22, null)
      .first<{ id: number }>()

    await env.KV.put(`agent:latest:${node?.id}`, JSON.stringify({ cpu_usage: 91, memory_usage: 84 }))

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Node evidence incident',
        source: 'node',
        severity: 'medium',
        action_ref: `node:${node?.id}`,
      }),
    }, env)

    expect(createRes.status).toBe(201)
    const createData = await createRes.json() as { data?: { evidence?: Array<{ source: string }> } }
    const evidence = createData.data?.evidence || []
    expect(evidence.some(item => item.source === 'nodes.record')).toBe(true)
    expect(evidence.some(item => item.source === 'nodes.latest_metrics')).toBe(true)
  })

  it('returns standardized execution result for restart incidents', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'incident-exec-standard@example.com', 'IncidentExec123!', 'admin')

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Standardized execution incident',
        source: 'alerts.rollout',
        severity: 'medium',
        action_type: 'restart_deployment',
        action_ref: 'default/anixops-api',
      }),
    }, env)

    const createData = await createRes.json() as { data?: { id: string } }
    await app.request(`/api/v1/incidents/${createData.data?.id}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    const executeRes = await app.request(`/api/v1/incidents/${createData.data?.id}/execute`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(executeRes.status).toBe(200)
    const executeData = await executeRes.json() as {
      data?: { execution_result?: { backend: string; success: boolean; operation: string; target?: { kind: string } } }
    }
    expect(executeData.data?.execution_result?.backend).toBe('kubernetes')
    expect(executeData.data?.execution_result?.success).toBe(true)
    expect(executeData.data?.execution_result?.operation).toBe('restart_deployment')
    expect(executeData.data?.execution_result?.target?.kind).toBe('deployment')
  })

  it('adds structured links for incident resources', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'incident-links@example.com', 'IncidentLinks123!', 'admin')

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Linked incident',
        source: 'task',
        severity: 'medium',
        action_ref: 'task:task-link-1',
      }),
    }, env)

    expect(createRes.status).toBe(201)
    const createData = await createRes.json() as { data?: { links?: Array<{ kind: string; href?: string }> } }
    expect((createData.data?.links || []).some((link) => link.kind === 'task')).toBe(true)
    expect((createData.data?.links || []).some((link) => link.href?.includes('/api/v1/tasks/'))).toBe(true)
  })

  it('blocks operator approval for critical incidents', async () => {
    const env = createEnv()
    const adminToken = await registerAndLogin(env, 'incident-admin@example.com', 'IncidentAdmin123!', 'admin')
    const operatorToken = await registerAndLogin(env, 'incident-operator@example.com', 'IncidentOperator123!', 'operator')

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        title: 'Critical restart incident',
        source: 'test-suite',
        severity: 'critical',
        action_type: 'restart_deployment',
        action_ref: 'default/anixops-api',
      }),
    }, env)

    const createData = await createRes.json() as { data?: { id: string } }
    const approveRes = await app.request(`/api/v1/incidents/${createData.data?.id}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${operatorToken}` },
    }, env)

    expect(approveRes.status).toBe(403)
  })

  it('blocks operator approval for scale_policy incidents', async () => {
    const env = createEnv()
    const adminToken = await registerAndLogin(env, 'incident-admin2@example.com', 'IncidentAdmin123!', 'admin')
    const operatorToken = await registerAndLogin(env, 'incident-operator2@example.com', 'IncidentOperator123!', 'operator')

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        title: 'Scale policy incident',
        source: 'test-suite',
        severity: 'medium',
        action_type: 'scale_policy',
        action_ref: 'policy-1',
      }),
    }, env)

    const createData = await createRes.json() as { data?: { id: string } }
    const approveRes = await app.request(`/api/v1/incidents/${createData.data?.id}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${operatorToken}` },
    }, env)

    expect(approveRes.status).toBe(403)
  })

  it('returns incident timeline with all events', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'incident-timeline@example.com', 'IncidentTimeline123!', 'admin')

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Timeline test incident',
        source: 'test-suite',
        severity: 'high',
        action_type: 'restart_deployment',
        action_ref: 'default/anixops-api',
        evidence: [{ type: 'manual', source: 'test', content: 'Initial evidence' }],
      }),
    }, env)

    const createData = await createRes.json() as { data?: { id: string } }
    const incidentId = createData.data?.id || ''

    // Get initial timeline (should have created event)
    const initialTimelineRes = await app.request(`/api/v1/incidents/${incidentId}/timeline`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(initialTimelineRes.status).toBe(200)
    const initialTimeline = await initialTimelineRes.json() as { success: boolean; data?: { events?: Array<{ type: string }> } }
    expect(initialTimeline.success).toBe(true)
    expect(initialTimeline.data?.events?.some(e => e.type === 'created')).toBe(true)

    // Approve and execute
    await app.request(`/api/v1/incidents/${incidentId}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    await app.request(`/api/v1/incidents/${incidentId}/execute`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    // Get final timeline (should have all events)
    const finalTimelineRes = await app.request(`/api/v1/incidents/${incidentId}/timeline`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(finalTimelineRes.status).toBe(200)
    const finalTimeline = await finalTimelineRes.json() as {
      success: boolean
      data?: {
        incident_id: string
        events?: Array<{ type: string; summary: string }>
        total_events: number
      }
    }
    expect(finalTimeline.success).toBe(true)
    expect(finalTimeline.data?.incident_id).toBe(incidentId)
    expect(finalTimeline.data?.total_events).toBeGreaterThan(1)

    const eventTypes = finalTimeline.data?.events?.map(e => e.type) || []
    expect(eventTypes).toContain('created')
    expect(eventTypes).toContain('approved')
    expect(eventTypes).toContain('resolved')
  })

  it('adds, lists, updates, and deletes incident comments', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'incident-comment@example.com', 'IncidentComment123!', 'admin')

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Comment test incident',
        source: 'test-suite',
        severity: 'medium',
      }),
    }, env)

    const createData = await createRes.json() as { data?: { id: string } }
    const incidentId = createData.data?.id || ''

    // Add a comment
    const addCommentRes = await app.request(`/api/v1/incidents/${incidentId}/comments`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        content: 'This is a test comment',
        visibility: 'public',
      }),
    }, env)

    expect(addCommentRes.status).toBe(201)
    const addCommentData = await addCommentRes.json() as { success: boolean; data?: { id: string; content: string } }
    expect(addCommentData.success).toBe(true)
    expect(addCommentData.data?.content).toBe('This is a test comment')
    const commentId = addCommentData.data?.id || ''

    // List comments
    const listCommentsRes = await app.request(`/api/v1/incidents/${incidentId}/comments`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(listCommentsRes.status).toBe(200)
    const listCommentsData = await listCommentsRes.json() as { success: boolean; data?: Array<{ id: string }> }
    expect(listCommentsData.success).toBe(true)
    expect(listCommentsData.data?.length).toBe(1)
    expect(listCommentsData.data?.[0]?.id).toBe(commentId)

    // Update comment
    const updateCommentRes = await app.request(`/api/v1/incidents/${incidentId}/comments/${commentId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        content: 'Updated comment content',
      }),
    }, env)

    expect(updateCommentRes.status).toBe(200)
    const updateCommentData = await updateCommentRes.json() as { success: boolean; data?: { content: string } }
    expect(updateCommentData.success).toBe(true)
    expect(updateCommentData.data?.content).toBe('Updated comment content')

    // Delete comment
    const deleteCommentRes = await app.request(`/api/v1/incidents/${incidentId}/comments/${commentId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(deleteCommentRes.status).toBe(200)

    // Verify deleted
    const listAfterDeleteRes = await app.request(`/api/v1/incidents/${incidentId}/comments`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    const listAfterDeleteData = await listAfterDeleteRes.json() as { success: boolean; data?: Array<{ id: string }> }
    expect(listAfterDeleteData.data?.length).toBe(0)
  })

  it('denies comment update from non-author', async () => {
    const env = createEnv()
    const authorToken = await registerAndLogin(env, 'comment-author@example.com', 'CommentAuthor123!', 'admin')
    const otherToken = await registerAndLogin(env, 'comment-other@example.com', 'CommentOther123!', 'admin')

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authorToken}`,
      },
      body: JSON.stringify({
        title: 'Comment permission test',
        source: 'test',
        severity: 'medium',
      }),
    }, env)

    const createData = await createRes.json() as { data?: { id: string } }
    const incidentId = createData.data?.id || ''

    const addCommentRes = await app.request(`/api/v1/incidents/${incidentId}/comments`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authorToken}`,
      },
      body: JSON.stringify({
        content: 'Comment by author',
      }),
    }, env)

    const addCommentData = await addCommentRes.json() as { data?: { id: string } }
    const commentId = addCommentData.data?.id || ''

    // Try to update with different user
    const updateRes = await app.request(`/api/v1/incidents/${incidentId}/comments/${commentId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${otherToken}`,
      },
      body: JSON.stringify({
        content: 'Attempted update',
      }),
    }, env)

    expect(updateRes.status).toBe(404)
  })

  it('returns incident statistics', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'incident-stats@example.com', 'IncidentStats123!', 'admin')

    // Create a few incidents with different severities and statuses
    await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Low severity incident',
        source: 'test-1',
        severity: 'low',
      }),
    }, env)

    await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Critical incident',
        source: 'test-2',
        severity: 'critical',
        action_type: 'restart_deployment',
        action_ref: 'default/app',
      }),
    }, env)

    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Medium incident to resolve',
        source: 'test-3',
        severity: 'medium',
        action_type: 'restart_deployment',
        action_ref: 'default/app',
      }),
    }, env)

    const createData = await createRes.json() as { data?: { id: string } }
    const incidentId = createData.data?.id || ''

    // Approve and execute to get a resolved incident
    await app.request(`/api/v1/incidents/${incidentId}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    await app.request(`/api/v1/incidents/${incidentId}/execute`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    // Get statistics
    const statsRes = await app.request('/api/v1/incidents/statistics', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(statsRes.status).toBe(200)
    const statsData = await statsRes.json() as {
      success: boolean
      data?: {
        total: number
        by_status: Record<string, number>
        by_severity: Record<string, number>
        by_action_type: Record<string, number>
        trends: { daily: Array<{ date: string }>; weekly: Array<{ week: string }> }
        action_success_rate: { total_executed: number; success_rate: number }
      }
    }
    expect(statsData.success).toBe(true)
    expect(statsData.data?.total).toBeGreaterThanOrEqual(3)
    expect(statsData.data?.by_status?.open).toBeGreaterThanOrEqual(2)
    expect(statsData.data?.by_status?.resolved).toBeGreaterThanOrEqual(1)
    expect(statsData.data?.by_severity?.low).toBeGreaterThanOrEqual(1)
    expect(statsData.data?.by_severity?.critical).toBeGreaterThanOrEqual(1)
    expect(statsData.data?.by_action_type?.restart_deployment).toBeGreaterThanOrEqual(2)
    expect(statsData.data?.trends?.daily?.length).toBe(30)
    expect(statsData.data?.trends?.weekly?.length).toBe(12)
    expect(statsData.data?.action_success_rate?.total_executed).toBeGreaterThanOrEqual(1)
    expect(statsData.data?.action_success_rate?.success_rate).toBeGreaterThanOrEqual(0)
  })

  it('performs bulk approve operations', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'bulk-approve@example.com', 'BulkApprove123!', 'admin')

    // Create multiple incidents
    const incidentIds: string[] = []
    for (let i = 0; i < 3; i++) {
      const createRes = await app.request('/api/v1/incidents', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          title: `Bulk test incident ${i}`,
          source: 'test',
          severity: 'medium',
          action_type: 'restart_deployment',
          action_ref: 'default/app',
        }),
      }, env)
      const data = await createRes.json() as { data?: { id: string } }
      incidentIds.push(data.data?.id || '')
    }

    // Bulk approve
    const bulkRes = await app.request('/api/v1/incidents/bulk/approve', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({ incident_ids: incidentIds }),
    }, env)

    expect(bulkRes.status).toBe(200)
    const bulkData = await bulkRes.json() as {
      success: boolean
      data?: { total: number; successful: string[]; failed: Array<{ id: string }> }
    }
    expect(bulkData.success).toBe(true)
    expect(bulkData.data?.total).toBe(3)
    expect(bulkData.data?.successful.length).toBe(3)
    expect(bulkData.data?.failed.length).toBe(0)
  })

  it('performs bulk execute operations', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'bulk-execute@example.com', 'BulkExecute123!', 'admin')

    // Create and approve multiple incidents
    const incidentIds: string[] = []
    for (let i = 0; i < 2; i++) {
      const createRes = await app.request('/api/v1/incidents', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          title: `Bulk execute incident ${i}`,
          source: 'test',
          severity: 'medium',
          action_type: 'restart_deployment',
          action_ref: 'default/app',
        }),
      }, env)
      const data = await createRes.json() as { data?: { id: string } }
      const id = data.data?.id || ''
      incidentIds.push(id)

      // Approve each
      await app.request(`/api/v1/incidents/${id}/approve`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${authToken}` },
      }, env)
    }

    // Bulk execute
    const bulkRes = await app.request('/api/v1/incidents/bulk/execute', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({ incident_ids: incidentIds }),
    }, env)

    expect(bulkRes.status).toBe(200)
    const bulkData = await bulkRes.json() as {
      success: boolean
      data?: { total: number; successful: string[]; failed: Array<{ id: string }> }
    }
    expect(bulkData.success).toBe(true)
    expect(bulkData.data?.total).toBe(2)
  })

  it('handles partial failures in bulk operations', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'bulk-partial@example.com', 'BulkPartial123!', 'admin')

    // Create one incident
    const createRes = await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Partial failure test',
        source: 'test',
        severity: 'medium',
        action_type: 'restart_deployment',
        action_ref: 'default/app',
      }),
    }, env)
    const data = await createRes.json() as { data?: { id: string } }
    const validId = data.data?.id || ''

    // Try to approve valid + invalid IDs
    const bulkRes = await app.request('/api/v1/incidents/bulk/approve', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        incident_ids: [validId, '00000000-0000-0000-0000-000000000000'],
      }),
    }, env)

    expect(bulkRes.status).toBe(200)
    const bulkData = await bulkRes.json() as {
      success: boolean
      data?: { total: number; successful: string[]; failed: Array<{ id: string; error: string }> }
    }
    expect(bulkData.success).toBe(true)
    expect(bulkData.data?.total).toBe(2)
    expect(bulkData.data?.successful.length).toBe(1)
    expect(bulkData.data?.failed.length).toBe(1)
    expect(bulkData.data?.failed[0]?.error).toContain('not found')
  })

  it('searches incidents by title and summary', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'search-test@example.com', 'SearchTest123!', 'admin')

    // Create incidents with different titles
    await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Database connection timeout',
        source: 'monitoring',
        severity: 'high',
        summary: 'Production database is not responding to connection requests',
      }),
    }, env)

    await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'API latency spike',
        source: 'alerts',
        severity: 'medium',
        summary: 'API response times exceeded threshold',
      }),
    }, env)

    await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Memory leak in worker',
        source: 'monitoring',
        severity: 'low',
      }),
    }, env)

    // Search for "database"
    const dbSearchRes = await app.request('/api/v1/incidents/search?q=database', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(dbSearchRes.status).toBe(200)
    const dbSearchData = await dbSearchRes.json() as {
      success: boolean
      data?: {
        items: Array<{ title: string; search_score: number; search_highlights: string[] }>
        total: number
        query: string
      }
    }
    expect(dbSearchData.success).toBe(true)
    expect(dbSearchData.data?.query).toBe('database')
    expect(dbSearchData.data?.total).toBeGreaterThanOrEqual(1)
    expect(dbSearchData.data?.items.some(i => i.title.includes('Database'))).toBe(true)

    // Search for "monitoring"
    const monSearchRes = await app.request('/api/v1/incidents/search?q=monitoring', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(monSearchRes.status).toBe(200)
    const monSearchData = await monSearchRes.json() as {
      success: boolean
      data?: { total: number }
    }
    expect(monSearchData.data?.total).toBeGreaterThanOrEqual(2)
  })

  it('searches incidents with filters', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'search-filter@example.com', 'SearchFilter123!', 'admin')

    // Create incidents with different severities
    await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'Critical system failure',
        source: 'alerts',
        severity: 'critical',
      }),
    }, env)

    await app.request('/api/v1/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        title: 'System maintenance reminder',
        source: 'scheduler',
        severity: 'low',
      }),
    }, env)

    // Search for "system" with severity filter
    const searchRes = await app.request('/api/v1/incidents/search?q=system&severity=critical', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(searchRes.status).toBe(200)
    const searchData = await searchRes.json() as {
      success: boolean
      data?: { total: number; items: Array<{ severity: string }> }
    }
    expect(searchData.success).toBe(true)
    expect(searchData.data?.items.every(i => i.severity === 'critical')).toBe(true)
  })

  it('returns empty results for non-matching query', async () => {
    const env = createEnv()
    const authToken = await registerAndLogin(env, 'search-empty@example.com', 'SearchEmpty123!', 'admin')

    const searchRes = await app.request('/api/v1/incidents/search?q=nonexistentqueryterm', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(searchRes.status).toBe(200)
    const searchData = await searchRes.json() as { success: boolean; data?: { total: number } }
    expect(searchData.success).toBe(true)
    expect(searchData.data?.total).toBe(0)
  })
})
