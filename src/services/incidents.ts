import type {
  AuthPrincipal,
  Env,
  IncidentActionType,
  IncidentComment,
  IncidentCommentInput,
  IncidentDetail,
  IncidentEvidence,
  IncidentExecutionResult,
  IncidentRecord,
  IncidentRecommendation,
  IncidentSeverity,
  IncidentStatus,
  IncidentSummary,
} from '../types'
import { evaluateScalingPolicy, executeScalingAction, getScalingPolicy, type ScalingDecision } from './autoscaling'
import { listDeployments, listEvents, restartDeployment, scaleDeployment } from './kubernetes'
import { generateText, AI_MODELS } from './ai'
import { buildIncidentChannels, makeRealtimeEvent, publishRealtimeEvent } from './realtime'
import { getActivePolicy, evaluatePolicy } from './governance'
import { triggerWebhooks } from './webhooks'

const INCIDENT_PREFIX = 'incident:'
const INCIDENT_INDEX_KEY = `${INCIDENT_PREFIX}index`

export interface CreateIncidentInput {
  title: string
  severity?: IncidentSeverity
  source: string
  summary?: string
  correlation_id?: string
  evidence?: IncidentEvidence[]
  action_type?: IncidentActionType
  action_ref?: string
  tags?: string[]
}

export interface IncidentListFilters {
  status?: IncidentStatus
  severity?: IncidentSeverity
  action_type?: IncidentActionType
  source?: string
  requested_via?: 'jwt' | 'api_key'
  approved_by?: number
  correlation_id?: string
  has_action?: boolean
  tags?: string[]
  page?: number
  per_page?: number
  sort?: 'created_at' | 'updated_at' | 'severity' | 'status'
  order?: 'asc' | 'desc'
}

export interface IncidentListResult {
  items: IncidentRecord[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface IncidentSearchParams {
  query: string
  status?: IncidentStatus[]
  severity?: IncidentSeverity[]
  action_type?: IncidentActionType[]
  source?: string[]
  created_after?: string
  created_before?: string
  page?: number
  per_page?: number
}

export interface IncidentSearchResult {
  items: Array<IncidentRecord & { search_score: number; search_highlights: string[] }>
  total: number
  page: number
  per_page: number
  total_pages: number
  query: string
}

function nowIso(): string {
  return new Date().toISOString()
}

async function getIncidentIndex(env: Env): Promise<string[]> {
  return (await env.KV.get(INCIDENT_INDEX_KEY, 'json') as string[] | null) || []
}

async function setIncidentIndex(env: Env, ids: string[]): Promise<void> {
  await env.KV.put(INCIDENT_INDEX_KEY, JSON.stringify(ids.slice(0, 200)), { expirationTtl: 86400 * 30 })
}

function incidentKey(id: string): string {
  return `${INCIDENT_PREFIX}${id}`
}

function serializeIncident(incident: IncidentRecord) {
  return {
    ...incident,
    evidence: JSON.stringify(incident.evidence),
    recommendations: JSON.stringify(incident.recommendations),
    links: incident.links ? JSON.stringify(incident.links) : null,
    analysis: incident.analysis ? JSON.stringify(incident.analysis) : null,
    execution_result: incident.execution_result ? JSON.stringify(incident.execution_result) : null,
    tags: JSON.stringify(incident.tags || []),
  }
}

function deserializeIncident(record: Record<string, unknown>): IncidentRecord {
  return {
    ...(record as unknown as IncidentRecord),
    evidence: typeof record.evidence === 'string' ? JSON.parse(record.evidence) : ((record.evidence as IncidentRecord['evidence']) || []),
    recommendations: typeof record.recommendations === 'string' ? JSON.parse(record.recommendations) : ((record.recommendations as IncidentRecord['recommendations']) || []),
    links: typeof record.links === 'string' ? JSON.parse(record.links) : (record.links as IncidentRecord['links']),
    analysis: typeof record.analysis === 'string' ? JSON.parse(record.analysis) : (record.analysis as IncidentRecord['analysis']),
    execution_result: typeof record.execution_result === 'string' ? JSON.parse(record.execution_result) : (record.execution_result as IncidentRecord['execution_result']),
    tags: typeof record.tags === 'string' ? JSON.parse(record.tags) : ((record.tags as IncidentRecord['tags']) || []),
  }
}

export async function storeIncident(env: Env, incident: IncidentRecord): Promise<void> {
  const serialized = serializeIncident(incident)

  await env.DB
    .prepare(`
      INSERT OR REPLACE INTO incidents (
        id, title, summary, status, severity, source, correlation_id,
        requested_by, requested_by_email, requested_via, approved_by, approved_at,
        execution_id, action_type, action_ref, evidence, recommendations,
        links, analysis, execution_result, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      serialized.id,
      serialized.title,
      serialized.summary || null,
      serialized.status,
      serialized.severity,
      serialized.source,
      serialized.correlation_id,
      serialized.requested_by,
      serialized.requested_by_email || null,
      serialized.requested_via,
      serialized.approved_by || null,
      serialized.approved_at || null,
      serialized.execution_id || null,
      serialized.action_type || null,
      serialized.action_ref || null,
      serialized.evidence,
      serialized.recommendations,
      serialized.links,
      serialized.analysis,
      serialized.execution_result,
      serialized.created_at,
      serialized.updated_at,
    )
    .run()

  await env.KV.put(incidentKey(incident.id), JSON.stringify(incident), { expirationTtl: 86400 * 30 })
  const ids = await getIncidentIndex(env)
  if (!ids.includes(incident.id)) {
    ids.unshift(incident.id)
    await setIncidentIndex(env, ids)
  }
}

export async function getIncident(env: Env, id: string): Promise<IncidentRecord | null> {
  const record = await env.DB
    .prepare('SELECT * FROM incidents WHERE id = ?')
    .bind(id)
    .first<Record<string, unknown>>()

  if (record) {
    return deserializeIncident(record)
  }

  return await env.KV.get(incidentKey(id), 'json') as IncidentRecord | null
}

export async function listIncidents(env: Env, filters: IncidentListFilters = {}): Promise<IncidentListResult> {
  const page = Math.max(1, filters.page || 1)
  const perPage = Math.max(1, Math.min(filters.per_page || 20, 100))
  const sort = filters.sort || 'created_at'
  const order = filters.order || 'desc'

  let sql = 'SELECT * FROM incidents WHERE 1=1'
  let countSql = 'SELECT COUNT(*) as total FROM incidents WHERE 1=1'
  const params: Array<string | number> = []

  if (filters.status) {
    sql += ' AND status = ?'
    countSql += ' AND status = ?'
    params.push(filters.status)
  }
  if (filters.severity) {
    sql += ' AND severity = ?'
    countSql += ' AND severity = ?'
    params.push(filters.severity)
  }
  if (filters.action_type) {
    sql += ' AND action_type = ?'
    countSql += ' AND action_type = ?'
    params.push(filters.action_type)
  }
  if (filters.source) {
    sql += ' AND source = ?'
    countSql += ' AND source = ?'
    params.push(filters.source)
  }
  if (filters.requested_via) {
    sql += ' AND requested_via = ?'
    countSql += ' AND requested_via = ?'
    params.push(filters.requested_via)
  }
  if (filters.approved_by) {
    sql += ' AND approved_by = ?'
    countSql += ' AND approved_by = ?'
    params.push(filters.approved_by)
  }
  if (filters.correlation_id) {
    sql += ' AND correlation_id = ?'
    countSql += ' AND correlation_id = ?'
    params.push(filters.correlation_id)
  }
  if (typeof filters.has_action === 'boolean') {
    const clause = filters.has_action
      ? ' AND action_type IS NOT NULL AND action_ref IS NOT NULL'
      : ' AND (action_type IS NULL OR action_ref IS NULL)'
    sql += clause
    countSql += clause
  }

  sql += ` ORDER BY ${sort} ${order.toUpperCase()} LIMIT ? OFFSET ?`
  const pagedParams = [...params, perPage, (page - 1) * perPage]

  const countResult = await env.DB
    .prepare(countSql)
    .bind(...params)
    .first<{ total: number }>()

  const result = await env.DB
    .prepare(sql)
    .bind(...pagedParams)
    .all<Record<string, unknown>>()

  if (result.results.length > 0 || (countResult?.total || 0) > 0) {
    const total = countResult?.total || 0
    return {
      items: result.results.map(deserializeIncident),
      total,
      page,
      per_page: perPage,
      total_pages: Math.max(1, Math.ceil(total / perPage)),
    }
  }

  const ids = await getIncidentIndex(env)
  const incidents = await Promise.all(ids.map(id => getIncident(env, id)))
  const filtered = incidents
    .filter((incident): incident is IncidentRecord => !!incident)
    .filter((incident) => {
      if (filters.status && incident.status !== filters.status) return false
      if (filters.severity && incident.severity !== filters.severity) return false
      if (filters.action_type && incident.action_type !== filters.action_type) return false
      if (filters.source && incident.source !== filters.source) return false
      if (filters.requested_via && incident.requested_via !== filters.requested_via) return false
      if (filters.approved_by && incident.approved_by !== filters.approved_by) return false
      if (filters.correlation_id && incident.correlation_id !== filters.correlation_id) return false
      if (typeof filters.has_action === 'boolean') {
        const hasAction = !!incident.action_type && !!incident.action_ref
        if (hasAction !== filters.has_action) return false
      }
      return true
    })

  const sorted = [...filtered].sort((a, b) => {
    const left = String((a as unknown as Record<string, unknown>)[sort] || '')
    const right = String((b as unknown as Record<string, unknown>)[sort] || '')
    return order === 'asc' ? left.localeCompare(right) : right.localeCompare(left)
  })

  const items = sorted.slice((page - 1) * perPage, page * perPage)
  return {
    items,
    total: filtered.length,
    page,
    per_page: perPage,
    total_pages: Math.max(1, Math.ceil(filtered.length / perPage)),
  }
}

function buildDefaultRecommendations(actionType?: IncidentActionType, actionRef?: string): IncidentRecommendation[] {
  if (!actionType || !actionRef) {
    return []
  }

  return [{
    id: crypto.randomUUID(),
    title: 'Execute bounded remediation',
    description: `Execute approved ${actionType} action for reference ${actionRef}`,
    action_type: actionType,
    action_ref: actionRef,
    confidence: 0.7,
  }]
}

async function collectTaskEvidence(env: Env, actionRef: string): Promise<IncidentEvidence[]> {
  const task = await env.DB
    .prepare(`
      SELECT t.*, p.name as playbook_name
      FROM tasks t
      LEFT JOIN playbooks p ON t.playbook_id = p.id
      WHERE t.task_id = ? OR t.id = ?
    `)
    .bind(actionRef, actionRef)
    .first<Record<string, unknown> & { task_id?: string }>()

  if (!task) {
    return []
  }

  const logs = await env.DB
    .prepare(`
      SELECT * FROM task_logs
      WHERE task_id = ?
      ORDER BY created_at ASC
      LIMIT 10
    `)
    .bind(task.task_id || actionRef)
    .all<Record<string, unknown>>()

  return [
    {
      type: 'task',
      source: 'tasks.record',
      content: JSON.stringify(task),
    },
    ...logs.results.map((log) => ({
      type: 'log' as const,
      source: 'tasks.log',
      content: JSON.stringify(log),
    })),
  ]
}

async function collectNodeEvidence(env: Env, actionRef: string): Promise<IncidentEvidence[]> {
  const nodeId = actionRef.startsWith('node:') ? actionRef.slice(5) : actionRef
  const node = await env.DB
    .prepare('SELECT * FROM nodes WHERE id = ?')
    .bind(nodeId)
    .first<Record<string, unknown>>()

  if (!node) {
    return []
  }

  const latestMetrics = await env.KV.get(`agent:latest:${(node as { agent_id?: string }).agent_id || nodeId}`, 'json') as Record<string, unknown> | null

  return [
    {
      type: 'node',
      source: 'nodes.record',
      content: JSON.stringify(node),
    },
    ...(latestMetrics ? [{
      type: 'metric' as const,
      source: 'nodes.latest_metrics',
      content: JSON.stringify(latestMetrics),
    }] : []),
  ]
}

async function collectIncidentEvidence(env: Env, input: CreateIncidentInput): Promise<IncidentEvidence[]> {
  const evidence: IncidentEvidence[] = [...(input.evidence || [])]

  if (input.action_ref?.startsWith('task:') || input.source === 'task') {
    const taskRef = input.action_ref?.startsWith('task:') ? input.action_ref.slice(5) : input.action_ref
    if (taskRef) {
      evidence.push(...await collectTaskEvidence(env, taskRef))
    }
  }

  if (input.action_ref?.startsWith('node:') || input.source === 'node') {
    evidence.push(...await collectNodeEvidence(env, input.action_ref || input.source))
  }

  if (input.action_type === 'scale_policy' && input.action_ref) {
    const policy = await getScalingPolicy(env, input.action_ref)
    if (policy) {
      evidence.push({
        type: 'metric',
        source: 'autoscaling.policy',
        content: JSON.stringify({
          policy_id: policy.id,
          target_type: policy.targetType,
          target_id: policy.targetId,
          namespace: policy.namespace,
          min_replicas: policy.minReplicas,
          max_replicas: policy.maxReplicas,
          metrics: policy.metrics,
        }),
      })
    }
  }

  if (input.action_type === 'restart_deployment' && input.action_ref) {
    const [namespace, name] = input.action_ref.split('/', 2)
    if (namespace && name) {
      const [deployments, events] = await Promise.all([
        listDeployments(env, namespace),
        listEvents(env, namespace),
      ])

      const deployment = deployments.find((item) => item.name === name)
      if (deployment) {
        evidence.push({
          type: 'service',
          source: 'kubernetes.deployment',
          content: JSON.stringify({
            namespace,
            name: deployment.name,
            replicas: deployment.replicas,
            ready_replicas: deployment.readyReplicas,
            available_replicas: deployment.availableReplicas,
            containers: deployment.containers,
          }),
        })
      }

      const relatedEvents = events
        .filter((event) => event.involvedObject.name === name || event.involvedObject.name.startsWith(`${name}-`))
        .slice(0, 5)
      for (const event of relatedEvents) {
        evidence.push({
          type: 'alert',
          source: 'kubernetes.event',
          content: JSON.stringify({
            namespace,
            reason: event.reason,
            message: event.message,
            type: event.type,
            last_timestamp: event.lastTimestamp,
          }),
        })
      }
    }
  }

  return evidence
}

function publishIncidentEvent(env: Env, incident: IncidentRecord, type: string): void {
  publishRealtimeEvent(makeRealtimeEvent(
    type,
    'incident',
    buildIncidentChannels(incident.id, incident.requested_by),
    {
      incident_id: incident.id,
      status: incident.status,
      severity: incident.severity,
      title: incident.title,
      action_type: incident.action_type,
      action_ref: incident.action_ref,
    },
    {
      user_id: incident.requested_by,
      correlation_id: incident.correlation_id,
      resource: {
        kind: 'incident',
        id: incident.id,
        name: incident.title,
      },
    }
  ))

  // Trigger webhooks (async, non-blocking)
  triggerWebhooks(env, type as import('../types').WebhookEventType, incident).catch(() => {
    // Silently fail webhook triggers
  })
}

function buildIncidentLinks(input: CreateIncidentInput): IncidentRecord['links'] {
  const links: NonNullable<IncidentRecord['links']> = []

  if (!input.action_ref) {
    return links
  }

  if (input.action_type === 'scale_policy') {
    links.push({
      kind: 'scaling_policy',
      id: input.action_ref,
      href: `/api/v1/scaling/policies/${input.action_ref}`,
    })
  }

  if (input.action_type === 'restart_deployment') {
    const [namespace, name] = input.action_ref.split('/', 2)
    if (namespace && name) {
      links.push({
        kind: 'deployment',
        id: `${namespace}/${name}`,
        name,
        href: `/api/v1/kubernetes/namespaces/${namespace}/deployments/${name}`,
      })
    }
  }

  if (input.action_ref.startsWith('task:')) {
    const id = input.action_ref.slice(5)
    links.push({
      kind: 'task',
      id,
      href: `/api/v1/tasks/${id}`,
    })
  }

  if (input.action_ref.startsWith('node:')) {
    const id = input.action_ref.slice(5)
    links.push({
      kind: 'node',
      id,
      href: `/api/v1/nodes/${id}`,
    })
  }

  return links
}

export function toIncidentSummary(incident: IncidentRecord): IncidentSummary {
  return {
    id: incident.id,
    title: incident.title,
    summary: incident.summary,
    status: incident.status,
    severity: incident.severity,
    source: incident.source,
    requested_via: incident.requested_via,
    action_type: incident.action_type,
    action_ref: incident.action_ref,
    approved_by: incident.approved_by,
    correlation_id: incident.correlation_id,
    links: incident.links,
    tags: incident.tags || [],
    created_at: incident.created_at,
    updated_at: incident.updated_at,
  }
}

export function toIncidentDetail(incident: IncidentRecord): IncidentDetail {
  return {
    ...toIncidentSummary(incident),
    requested_by: incident.requested_by,
    requested_by_email: incident.requested_by_email,
    approved_at: incident.approved_at,
    execution_id: incident.execution_id,
    evidence: incident.evidence,
    recommendations: incident.recommendations,
    analysis: incident.analysis,
    execution_result: incident.execution_result,
  }
}

export async function canApproveIncident(env: Env, principal: AuthPrincipal, incident: IncidentRecord): Promise<boolean> {
  const policy = await getActivePolicy(env)
  const evaluation = evaluatePolicy(policy, principal, incident)
  return evaluation.allowed
}

export async function canExecuteIncident(env: Env, principal: AuthPrincipal, incident: IncidentRecord): Promise<boolean> {
  // Execution uses the same policy as approval
  return canApproveIncident(env, principal, incident)
}

export async function createIncident(env: Env, principal: AuthPrincipal, input: CreateIncidentInput): Promise<IncidentRecord> {
  const timestamp = nowIso()
  const evidence = await collectIncidentEvidence(env, input)
  const incident: IncidentRecord = {
    id: crypto.randomUUID(),
    title: input.title,
    summary: input.summary,
    status: 'open',
    severity: input.severity || 'medium',
    source: input.source,
    correlation_id: input.correlation_id || crypto.randomUUID(),
    requested_by: principal.sub,
    requested_by_email: principal.email,
    requested_via: principal.auth_method,
    action_type: input.action_type,
    action_ref: input.action_ref,
    evidence,
    recommendations: buildDefaultRecommendations(input.action_type, input.action_ref),
    links: buildIncidentLinks(input),
    tags: input.tags || [],
    created_at: timestamp,
    updated_at: timestamp,
  }

  await storeIncident(env, incident)
  publishIncidentEvent(env, incident, 'incident.created')
  return incident
}

export async function analyzeIncident(env: Env, incident: IncidentRecord): Promise<IncidentRecord> {
  const prompt = `Analyze this infrastructure incident and return strict JSON with keys: summary, severity, likely_cause, recommended_actions.\n\nTitle: ${incident.title}\nSource: ${incident.source}\nCurrent Severity: ${incident.severity}\nSummary: ${incident.summary || 'N/A'}\nEvidence: ${JSON.stringify(incident.evidence)}`

  const result = await generateText(env, prompt, {
    model: AI_MODELS.textGenerationFast,
    maxTokens: 256,
    temperature: 0.2,
    systemPrompt: 'You are an incident response assistant for DevOps workflows. Return concise JSON only.',
  })

  let analysis: Record<string, unknown> = {
    summary: incident.summary || incident.title,
    severity: incident.severity,
    likely_cause: 'Unknown',
    recommended_actions: incident.recommendations.map(r => r.title),
  }

  if (result.success && result.data) {
    const response = result.data as { response?: string; result?: { response?: string } }
    const text = typeof response === 'string'
      ? response
      : typeof response?.response === 'string'
        ? response.response
        : typeof response?.result?.response === 'string'
          ? response.result.response
          : ''

    if (text) {
      try {
        analysis = JSON.parse(text) as Record<string, unknown>
      } catch {
        analysis = {
          ...analysis,
          raw_response: text,
        }
      }
    }
  }

  const recommendations = incident.recommendations.length > 0
    ? incident.recommendations
    : [{
        id: crypto.randomUUID(),
        title: 'Review evidence and choose bounded remediation',
        description: 'Incident was analyzed but no executable remediation reference was supplied.',
      }]

  const updated: IncidentRecord = {
    ...incident,
    status: 'analyzed',
    summary: typeof analysis.summary === 'string' ? analysis.summary : incident.summary,
    analysis,
    recommendations,
    updated_at: nowIso(),
  }

  await storeIncident(env, updated)
  publishIncidentEvent(env, updated, 'incident.analyzed')
  return updated
}

export async function approveIncident(env: Env, incident: IncidentRecord, principal: AuthPrincipal): Promise<IncidentRecord> {
  const updated: IncidentRecord = {
    ...incident,
    status: 'approved',
    approved_by: principal.sub,
    approved_at: nowIso(),
    updated_at: nowIso(),
  }

  await storeIncident(env, updated)
  publishIncidentEvent(env, updated, 'incident.approved')
  return updated
}

async function resolveScalingDecision(env: Env, incident: IncidentRecord): Promise<ScalingDecision> {
  if (!incident.action_ref) {
    throw new Error('Incident has no action reference')
  }

  const policy = await getScalingPolicy(env, incident.action_ref)
  if (!policy) {
    throw new Error('Scaling policy not found')
  }

  return evaluateScalingPolicy(env, policy)
}

async function executeRestartDeployment(env: Env, actionRef: string): Promise<{ success: boolean; execution_id: string; result: Record<string, unknown> }> {
  const [namespace, name] = actionRef.split('/', 2)
  if (!namespace || !name) {
    throw new Error('restart_deployment action_ref must be <namespace>/<deployment>')
  }

  const success = await restartDeployment(env, namespace, name)
  return {
    success,
    execution_id: crypto.randomUUID(),
    result: {
      namespace,
      deployment: name,
      restarted: success,
    },
  }
}

async function executeScaleDeployment(env: Env, actionRef: string): Promise<{ success: boolean; execution_id: string; result: Record<string, unknown> }> {
  // Format: <namespace>/<deployment>/<replicas>
  const parts = actionRef.split('/')
  if (parts.length !== 3) {
    throw new Error('scale_deployment action_ref must be <namespace>/<deployment>/<replicas>')
  }

  const [namespace, name, replicasStr] = parts
  const replicas = parseInt(replicasStr, 10)
  if (isNaN(replicas) || replicas < 0 || replicas > 1000) {
    throw new Error('Replicas must be a valid number between 0 and 1000')
  }

  const success = await scaleDeployment(env, namespace, name, replicas)
  return {
    success,
    execution_id: crypto.randomUUID(),
    result: {
      namespace,
      deployment: name,
      replicas,
      scaled: success,
    },
  }
}

export async function executeIncident(env: Env, incident: IncidentRecord): Promise<IncidentRecord> {
  if (incident.status !== 'approved') {
    throw new Error('Incident must be approved before execution')
  }

  if (!incident.action_type || !incident.action_ref) {
    throw new Error('Unsupported or missing incident action')
  }

  const executing: IncidentRecord = {
    ...incident,
    status: 'executing',
    updated_at: nowIso(),
  }

  await storeIncident(env, executing)
  publishIncidentEvent(env, executing, 'incident.executing')

  const actionRef = executing.action_ref
  if (!actionRef) {
    throw new Error('Incident has no action reference')
  }

  let updated: IncidentRecord

  if (incident.action_type === 'scale_policy') {
    const decision = await resolveScalingDecision(env, executing)
    const result = await executeScalingAction(env, actionRef, decision)

    updated = {
      ...executing,
      status: result.success ? 'resolved' : 'failed',
      execution_id: result.event?.id,
      execution_result: result.success
        ? {
            backend: 'autoscaling',
            success: true,
            operation: decision.action,
            message: decision.reason,
            target: {
              kind: 'scaling_policy',
              id: actionRef,
            },
            details: {
              decision,
              event: result.event,
            },
          }
        : {
            backend: 'autoscaling',
            success: false,
            operation: decision.action,
            message: result.error,
            target: {
              kind: 'scaling_policy',
              id: actionRef,
            },
            details: {
              decision,
            },
          },
      updated_at: nowIso(),
    }
  } else if (incident.action_type === 'restart_deployment') {
    const result = await executeRestartDeployment(env, actionRef)
    updated = {
      ...executing,
      status: result.success ? 'resolved' : 'failed',
      execution_id: result.execution_id,
      execution_result: {
        backend: 'kubernetes',
        success: result.success,
        operation: 'restart_deployment',
        message: result.success ? 'Deployment restarted' : 'Deployment restart failed',
        target: {
          kind: 'deployment',
          id: actionRef,
          name: (result.result.deployment as string | undefined),
          namespace: (result.result.namespace as string | undefined),
        },
        details: result.result,
      },
      updated_at: nowIso(),
    }
  } else if (incident.action_type === 'scale_deployment') {
    const result = await executeScaleDeployment(env, actionRef)
    updated = {
      ...executing,
      status: result.success ? 'resolved' : 'failed',
      execution_id: result.execution_id,
      execution_result: {
        backend: 'kubernetes',
        success: result.success,
        operation: 'scale_deployment',
        message: result.success ? `Deployment scaled to ${result.result.replicas} replicas` : 'Deployment scaling failed',
        target: {
          kind: 'deployment',
          id: actionRef,
          name: (result.result.deployment as string | undefined),
          namespace: (result.result.namespace as string | undefined),
        },
        details: result.result,
      },
      updated_at: nowIso(),
    }
  } else {
    throw new Error('Unsupported incident action type')
  }

  await storeIncident(env, updated)
  publishIncidentEvent(env, updated, updated.status === 'resolved' ? 'incident.resolved' : 'incident.failed')
  return updated
}

export function buildIncidentTimeline(incident: IncidentRecord): import('../types').IncidentTimeline {
  const events: import('../types').IncidentTimelineEvent[] = []

  // Creation event
  events.push({
    id: `${incident.id}:created`,
    incident_id: incident.id,
    type: 'created',
    timestamp: incident.created_at,
    actor: {
      user_id: incident.requested_by,
      email: incident.requested_by_email,
    },
    summary: `Incident created: ${incident.title}`,
    details: {
      severity: incident.severity,
      source: incident.source,
      action_type: incident.action_type,
      action_ref: incident.action_ref,
    },
    metadata: {
      correlation_id: incident.correlation_id,
      requested_via: incident.requested_via,
      initial_evidence_count: incident.evidence.length,
    },
  })

  // Evidence added events (for enriched evidence beyond the first)
  if (incident.evidence.length > 0) {
    const enrichedEvidence = incident.evidence.slice(1)
    enrichedEvidence.forEach((evidence, index) => {
      events.push({
        id: `${incident.id}:evidence:${index}`,
        incident_id: incident.id,
        type: 'evidence_added',
        timestamp: incident.created_at,
        summary: `Evidence added: ${evidence.type} from ${evidence.source}`,
        details: {
          type: evidence.type,
          source: evidence.source,
          content_preview: evidence.content.substring(0, 200),
        },
      })
    })
  }

  // Analysis event (if incident was analyzed)
  if (incident.status !== 'open' && incident.analysis) {
    events.push({
      id: `${incident.id}:analyzed`,
      incident_id: incident.id,
      type: 'analyzed',
      timestamp: incident.updated_at,
      summary: incident.analysis.summary as string || 'Incident analyzed',
      details: {
        severity: incident.analysis.severity || incident.severity,
        likely_cause: incident.analysis.likely_cause,
        recommended_actions: incident.analysis.recommended_actions,
      },
      metadata: {
        recommendations_count: incident.recommendations.length,
      },
    })
  }

  // Approval event (if incident was approved)
  if (incident.approved_by && incident.approved_at) {
    events.push({
      id: `${incident.id}:approved`,
      incident_id: incident.id,
      type: 'approved',
      timestamp: incident.approved_at,
      actor: {
        user_id: incident.approved_by,
      },
      summary: 'Incident approved for execution',
      details: {
        action_type: incident.action_type,
        action_ref: incident.action_ref,
      },
    })
  }

  // Execution events (if incident was executed)
  if (incident.status === 'executing' || incident.status === 'resolved' || incident.status === 'failed') {
    if (incident.execution_result) {
      events.push({
        id: `${incident.id}:executing`,
        incident_id: incident.id,
        type: 'executing',
        timestamp: incident.updated_at,
        summary: `Executing ${incident.action_type} action`,
        details: {
          backend: incident.execution_result.backend,
          operation: incident.execution_result.operation,
          target: incident.execution_result.target,
        },
      })

      // Resolution/Failure event
      events.push({
        id: `${incident.id}:${incident.status}`,
        incident_id: incident.id,
        type: incident.status,
        timestamp: incident.updated_at,
        summary: incident.status === 'resolved'
          ? 'Incident resolved successfully'
          : 'Incident execution failed',
        details: {
          success: incident.execution_result.success,
          message: incident.execution_result.message,
          execution_id: incident.execution_id,
        },
        metadata: incident.execution_result.details,
      })
    }
  }

  // Sort by timestamp (oldest first)
  events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())

  return {
    incident_id: incident.id,
    correlation_id: incident.correlation_id,
    events,
    total_events: events.length,
  }
}

// Incident Comments
const COMMENT_PREFIX = 'incident:comment:'
const COMMENT_INDEX_PREFIX = 'incident:comments:'

function commentKey(commentId: string): string {
  return `${COMMENT_PREFIX}${commentId}`
}

function commentIndexKey(incidentId: string): string {
  return `${COMMENT_INDEX_PREFIX}${incidentId}`
}

export async function addIncidentComment(
  env: Env,
  incident: IncidentRecord,
  principal: AuthPrincipal,
  input: IncidentCommentInput
): Promise<IncidentComment> {
  const now = nowIso()
  const commentId = crypto.randomUUID()

  const comment: IncidentComment = {
    id: commentId,
    incident_id: incident.id,
    author_id: principal.sub,
    author_email: principal.email,
    author_role: principal.role,
    content: input.content,
    visibility: input.visibility || 'public',
    created_at: now,
    updated_at: now,
  }

  await env.KV.put(commentKey(commentId), JSON.stringify(comment), { expirationTtl: 86400 * 30 })

  const indexKey = commentIndexKey(incident.id)
  const index = (await env.KV.get(indexKey, 'json') as string[] | null) || []
  index.unshift(commentId)
  await env.KV.put(indexKey, JSON.stringify(index.slice(0, 100)), { expirationTtl: 86400 * 30 })

  return comment
}

export async function getIncidentComment(env: Env, commentId: string): Promise<IncidentComment | null> {
  return await env.KV.get(commentKey(commentId), 'json') as IncidentComment | null
}

export async function listIncidentComments(env: Env, incidentId: string): Promise<IncidentComment[]> {
  const indexKey = commentIndexKey(incidentId)
  const index = (await env.KV.get(indexKey, 'json') as string[] | null) || []

  const comments = await Promise.all(
    index.map(id => getIncidentComment(env, id))
  )

  return comments.filter((c): c is IncidentComment => c !== null)
}

export async function updateIncidentComment(
  env: Env,
  commentId: string,
  principal: AuthPrincipal,
  content: string
): Promise<IncidentComment | null> {
  const comment = await getIncidentComment(env, commentId)
  if (!comment) {
    return null
  }

  // Only the author can update the comment
  if (comment.author_id !== principal.sub) {
    return null
  }

  const updated: IncidentComment = {
    ...comment,
    content,
    updated_at: nowIso(),
  }

  await env.KV.put(commentKey(commentId), JSON.stringify(updated), { expirationTtl: 86400 * 30 })
  return updated
}

export async function deleteIncidentComment(
  env: Env,
  commentId: string,
  principal: AuthPrincipal
): Promise<boolean> {
  const comment = await getIncidentComment(env, commentId)
  if (!comment) {
    return false
  }

  // Only the author or an admin can delete the comment
  if (comment.author_id !== principal.sub && principal.role !== 'admin') {
    return false
  }

  await env.KV.delete(commentKey(commentId))

  // Remove from index
  const indexKey = commentIndexKey(comment.incident_id)
  const index = (await env.KV.get(indexKey, 'json') as string[] | null) || []
  const newIndex = index.filter(id => id !== commentId)
  await env.KV.put(indexKey, JSON.stringify(newIndex), { expirationTtl: 86400 * 30 })

  return true
}

// Incident Statistics
export interface IncidentStatistics {
  total: number
  by_status: Record<IncidentStatus, number>
  by_severity: Record<IncidentSeverity, number>
  by_action_type: Record<string, number>
  by_source: Record<string, number>
  by_auth_method: Record<string, number>
  time_metrics: {
    mean_time_to_approval_minutes: number | null
    mean_time_to_resolution_minutes: number | null
    median_time_to_resolution_minutes: number | null
  }
  trends: {
    daily: Array<{ date: string; created: number; resolved: number }>
    weekly: Array<{ week: string; created: number; resolved: number }>
  }
  action_success_rate: {
    total_executed: number
    successful: number
    failed: number
    success_rate: number
  }
}

export async function getIncidentStatistics(
  env: Env,
  options: { since?: string; until?: string } = {}
): Promise<IncidentStatistics> {
  const ids = await getIncidentIndex(env)
  const incidents = await Promise.all(ids.map(id => getIncident(env, id)))
  const validIncidents = incidents.filter((i): i is IncidentRecord => i !== null)

  // Filter by date range if provided
  let filtered = validIncidents
  if (options.since) {
    const sinceDate = new Date(options.since)
    filtered = filtered.filter(i => new Date(i.created_at) >= sinceDate)
  }
  if (options.until) {
    const untilDate = new Date(options.until)
    filtered = filtered.filter(i => new Date(i.created_at) <= untilDate)
  }

  // Count by status
  const byStatus: Record<IncidentStatus, number> = {
    open: 0,
    analyzed: 0,
    approved: 0,
    executing: 0,
    resolved: 0,
    failed: 0,
  }
  for (const i of filtered) {
    byStatus[i.status]++
  }

  // Count by severity
  const bySeverity: Record<IncidentSeverity, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  }
  for (const i of filtered) {
    bySeverity[i.severity]++
  }

  // Count by action type
  const byActionType: Record<string, number> = {}
  for (const i of filtered) {
    if (i.action_type) {
      byActionType[i.action_type] = (byActionType[i.action_type] || 0) + 1
    }
  }

  // Count by source
  const bySource: Record<string, number> = {}
  for (const i of filtered) {
    bySource[i.source] = (bySource[i.source] || 0) + 1
  }

  // Count by auth method
  const byAuthMethod: Record<string, number> = {}
  for (const i of filtered) {
    byAuthMethod[i.requested_via] = (byAuthMethod[i.requested_via] || 0) + 1
  }

  // Time metrics
  const approvedIncidents = filtered.filter(i => i.approved_at && i.created_at)
  const resolvedIncidents = filtered.filter(i => i.status === 'resolved' && i.execution_result)

  let meanTimeToApproval: number | null = null
  if (approvedIncidents.length > 0) {
    const approvalTimes = approvedIncidents.map(i =>
      (new Date(i.approved_at!).getTime() - new Date(i.created_at).getTime()) / 60000
    )
    meanTimeToApproval = approvalTimes.reduce((a, b) => a + b, 0) / approvalTimes.length
  }

  let meanTimeToResolution: number | null = null
  let medianTimeToResolution: number | null = null
  if (resolvedIncidents.length > 0) {
    const resolutionTimes = resolvedIncidents.map(i =>
      (new Date(i.updated_at).getTime() - new Date(i.created_at).getTime()) / 60000
    )
    meanTimeToResolution = resolutionTimes.reduce((a, b) => a + b, 0) / resolutionTimes.length

    const sorted = [...resolutionTimes].sort((a, b) => a - b)
    const mid = Math.floor(sorted.length / 2)
    medianTimeToResolution = sorted.length % 2 !== 0
      ? sorted[mid]
      : (sorted[mid - 1] + sorted[mid]) / 2
  }

  // Daily trends (last 30 days)
  const daily: Array<{ date: string; created: number; resolved: number }> = []
  const now = new Date()
  for (let d = 29; d >= 0; d--) {
    const date = new Date(now)
    date.setDate(date.getDate() - d)
    const dateStr = date.toISOString().split('T')[0]

    const createdCount = validIncidents.filter(i =>
      i.created_at.startsWith(dateStr)
    ).length

    const resolvedCount = validIncidents.filter(i =>
      i.status === 'resolved' && i.updated_at.startsWith(dateStr)
    ).length

    daily.push({ date: dateStr, created: createdCount, resolved: resolvedCount })
  }

  // Weekly trends (last 12 weeks)
  const weekly: Array<{ week: string; created: number; resolved: number }> = []
  for (let w = 11; w >= 0; w--) {
    const weekStart = new Date(now)
    weekStart.setDate(weekStart.getDate() - (w * 7 + now.getDay()))
    const weekEnd = new Date(weekStart)
    weekEnd.setDate(weekEnd.getDate() + 6)
    const weekStr = weekStart.toISOString().split('T')[0]

    const createdCount = validIncidents.filter(i => {
      const created = new Date(i.created_at)
      return created >= weekStart && created <= weekEnd
    }).length

    const resolvedCount = validIncidents.filter(i => {
      if (i.status !== 'resolved') return false
      const resolved = new Date(i.updated_at)
      return resolved >= weekStart && resolved <= weekEnd
    }).length

    weekly.push({ week: weekStr, created: createdCount, resolved: resolvedCount })
  }

  // Action success rate
  const executed = validIncidents.filter(i => i.execution_result)
  const successful = executed.filter(i => i.execution_result?.success).length
  const failed = executed.filter(i => !i.execution_result?.success).length

  return {
    total: filtered.length,
    by_status: byStatus,
    by_severity: bySeverity,
    by_action_type: byActionType,
    by_source: bySource,
    by_auth_method: byAuthMethod,
    time_metrics: {
      mean_time_to_approval_minutes: meanTimeToApproval,
      mean_time_to_resolution_minutes: meanTimeToResolution,
      median_time_to_resolution_minutes: medianTimeToResolution,
    },
    trends: {
      daily,
      weekly,
    },
    action_success_rate: {
      total_executed: executed.length,
      successful,
      failed,
      success_rate: executed.length > 0 ? (successful / executed.length) * 100 : 0,
    },
  }
}

// Bulk Operations
export interface BulkOperationResult {
  total: number
  successful: string[]
  failed: Array<{ id: string; error: string }>
}

export async function bulkApproveIncidents(
  env: Env,
  principal: AuthPrincipal,
  incidentIds: string[]
): Promise<BulkOperationResult> {
  const result: BulkOperationResult = {
    total: incidentIds.length,
    successful: [],
    failed: [],
  }

  for (const id of incidentIds) {
    try {
      const incident = await getIncident(env, id)
      if (!incident) {
        result.failed.push({ id, error: 'Incident not found' })
        continue
      }

      const canApprove = await canApproveIncident(env, principal, incident)
      if (!canApprove) {
        result.failed.push({ id, error: 'Forbidden: approval policy denies this action' })
        continue
      }

      if (incident.status !== 'open' && incident.status !== 'analyzed') {
        result.failed.push({ id, error: `Cannot approve incident in ${incident.status} state` })
        continue
      }

      await approveIncident(env, incident, principal)
      result.successful.push(id)
    } catch (err) {
      result.failed.push({ id, error: err instanceof Error ? err.message : 'Unknown error' })
    }
  }

  return result
}

export async function bulkExecuteIncidents(
  env: Env,
  principal: AuthPrincipal,
  incidentIds: string[]
): Promise<BulkOperationResult> {
  const result: BulkOperationResult = {
    total: incidentIds.length,
    successful: [],
    failed: [],
  }

  for (const id of incidentIds) {
    try {
      const incident = await getIncident(env, id)
      if (!incident) {
        result.failed.push({ id, error: 'Incident not found' })
        continue
      }

      const canExecute = await canExecuteIncident(env, principal, incident)
      if (!canExecute) {
        result.failed.push({ id, error: 'Forbidden: execution policy denies this action' })
        continue
      }

      if (incident.status !== 'approved') {
        result.failed.push({ id, error: `Cannot execute incident in ${incident.status} state` })
        continue
      }

      const updated = await executeIncident(env, incident)
      if (updated.status === 'resolved') {
        result.successful.push(id)
      } else {
        result.failed.push({ id, error: 'Execution failed' })
      }
    } catch (err) {
      result.failed.push({ id, error: err instanceof Error ? err.message : 'Unknown error' })
    }
  }

  return result
}

export async function bulkAnalyzeIncidents(
  env: Env,
  incidentIds: string[]
): Promise<BulkOperationResult> {
  const result: BulkOperationResult = {
    total: incidentIds.length,
    successful: [],
    failed: [],
  }

  for (const id of incidentIds) {
    try {
      const incident = await getIncident(env, id)
      if (!incident) {
        result.failed.push({ id, error: 'Incident not found' })
        continue
      }

      if (incident.status !== 'open') {
        result.failed.push({ id, error: `Cannot analyze incident in ${incident.status} state` })
        continue
      }

      await analyzeIncident(env, incident)
      result.successful.push(id)
    } catch (err) {
      result.failed.push({ id, error: err instanceof Error ? err.message : 'Unknown error' })
    }
  }

  return result
}

export async function bulkDeleteIncidents(
  env: Env,
  incidentIds: string[]
): Promise<BulkOperationResult> {
  const result: BulkOperationResult = {
    total: incidentIds.length,
    successful: [],
    failed: [],
  }

  for (const id of incidentIds) {
    try {
      const incident = await getIncident(env, id)
      if (!incident) {
        result.failed.push({ id, error: 'Incident not found' })
        continue
      }

      // Only allow deletion of resolved or failed incidents
      if (incident.status !== 'resolved' && incident.status !== 'failed') {
        result.failed.push({ id, error: `Cannot delete incident in ${incident.status} state` })
        continue
      }

      // Delete from D1
      await env.DB.prepare('DELETE FROM incidents WHERE id = ?').bind(id).run()

      // Delete from KV
      await env.KV.delete(incidentKey(id))

      // Remove from index
      const ids = await getIncidentIndex(env)
      const newIds = ids.filter(i => i !== id)
      await setIncidentIndex(env, newIds)

      result.successful.push(id)
    } catch (err) {
      result.failed.push({ id, error: err instanceof Error ? err.message : 'Unknown error' })
    }
  }

  return result
}

// Search Functions
function normalizeText(text: string): string {
  return text.toLowerCase().trim()
}

function tokenize(query: string): string[] {
  return normalizeText(query)
    .split(/\s+/)
    .filter(token => token.length > 1)
}

function matchText(text: string, tokens: string[]): { matches: number; highlights: string[] } {
  const normalized = normalizeText(text)
  const highlights: string[] = []
  let matches = 0

  for (const token of tokens) {
    if (normalized.includes(token)) {
      matches++
      // Extract surrounding context for highlight
      const index = normalized.indexOf(token)
      const start = Math.max(0, index - 20)
      const end = Math.min(normalized.length, index + token.length + 20)
      const context = text.substring(start, end)
      if (context && !highlights.includes(context)) {
        highlights.push(context.length < text.length ? `...${context}...` : context)
      }
    }
  }

  return { matches, highlights }
}

function calculateSearchScore(incident: IncidentRecord, tokens: string[]): { score: number; highlights: string[] } {
  let totalScore = 0
  const allHighlights: string[] = []

  // Title matches are weighted highest
  if (incident.title) {
    const { matches, highlights } = matchText(incident.title, tokens)
    totalScore += matches * 10
    allHighlights.push(...highlights.slice(0, 2))
  }

  // Summary matches
  if (incident.summary) {
    const { matches, highlights } = matchText(incident.summary, tokens)
    totalScore += matches * 5
    allHighlights.push(...highlights.slice(0, 2))
  }

  // Source matches
  const sourceResult = matchText(incident.source, tokens)
  totalScore += sourceResult.matches * 3

  // Evidence content matches
  for (const evidence of incident.evidence) {
    const { matches, highlights } = matchText(evidence.content, tokens)
    totalScore += matches * 2
    allHighlights.push(...highlights.slice(0, 1))
  }

  // Analysis matches
  if (incident.analysis) {
    const analysisStr = JSON.stringify(incident.analysis)
    const { matches, highlights } = matchText(analysisStr, tokens)
    totalScore += matches * 2
    allHighlights.push(...highlights.slice(0, 1))
  }

  // Deduplicate highlights
  const uniqueHighlights = [...new Set(allHighlights)].slice(0, 5)

  return { score: totalScore, highlights: uniqueHighlights }
}

export async function searchIncidents(
  env: Env,
  params: IncidentSearchParams
): Promise<IncidentSearchResult> {
  const page = Math.max(1, params.page || 1)
  const perPage = Math.max(1, Math.min(params.per_page || 20, 100))
  const tokens = tokenize(params.query)

  if (tokens.length === 0) {
    return {
      items: [],
      total: 0,
      page,
      per_page: perPage,
      total_pages: 0,
      query: params.query,
    }
  }

  // Get all incidents
  const ids = await getIncidentIndex(env)
  const incidents = await Promise.all(ids.map(id => getIncident(env, id)))
  const validIncidents = incidents.filter((i): i is IncidentRecord => i !== null)

  // Filter by status
  let filtered = validIncidents
  if (params.status?.length) {
    filtered = filtered.filter(i => params.status!.includes(i.status))
  }

  // Filter by severity
  if (params.severity?.length) {
    filtered = filtered.filter(i => params.severity!.includes(i.severity))
  }

  // Filter by action_type
  if (params.action_type?.length) {
    filtered = filtered.filter(i => i.action_type && params.action_type!.includes(i.action_type))
  }

  // Filter by source
  if (params.source?.length) {
    filtered = filtered.filter(i => params.source!.some(s =>
      normalizeText(i.source).includes(normalizeText(s))
    ))
  }

  // Filter by created_after
  if (params.created_after) {
    const afterDate = new Date(params.created_after)
    filtered = filtered.filter(i => new Date(i.created_at) >= afterDate)
  }

  // Filter by created_before
  if (params.created_before) {
    const beforeDate = new Date(params.created_before)
    filtered = filtered.filter(i => new Date(i.created_at) <= beforeDate)
  }

  // Search and score
  const scored = filtered
    .map(incident => {
      const { score, highlights } = calculateSearchScore(incident, tokens)
      return { incident, score, highlights }
    })
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score)

  const paginated = scored.slice((page - 1) * perPage, page * perPage)

  return {
    items: paginated.map(item => ({
      ...item.incident,
      search_score: item.score,
      search_highlights: item.highlights,
    })),
    total: scored.length,
    page,
    per_page: perPage,
    total_pages: Math.max(1, Math.ceil(scored.length / perPage)),
    query: params.query,
  }
}

// Tag Management Functions
export async function addIncidentTags(
  env: Env,
  incident: IncidentRecord,
  tags: string[]
): Promise<IncidentRecord> {
  const uniqueTags = [...new Set([...(incident.tags || []), ...tags])]
    .map(t => t.toLowerCase().trim())
    .filter(t => t.length > 0)

  const updated: IncidentRecord = {
    ...incident,
    tags: uniqueTags,
    updated_at: nowIso(),
  }

  await storeIncident(env, updated)
  return updated
}

export async function removeIncidentTags(
  env: Env,
  incident: IncidentRecord,
  tags: string[]
): Promise<IncidentRecord> {
  const tagsToRemove = tags.map(t => t.toLowerCase().trim())
  const remainingTags = (incident.tags || []).filter(t => !tagsToRemove.includes(t.toLowerCase()))

  const updated: IncidentRecord = {
    ...incident,
    tags: remainingTags,
    updated_at: nowIso(),
  }

  await storeIncident(env, updated)
  return updated
}

export async function setIncidentTags(
  env: Env,
  incident: IncidentRecord,
  tags: string[]
): Promise<IncidentRecord> {
  const uniqueTags = [...new Set(tags.map(t => t.toLowerCase().trim()).filter(t => t.length > 0))]

  const updated: IncidentRecord = {
    ...incident,
    tags: uniqueTags,
    updated_at: nowIso(),
  }

  await storeIncident(env, updated)
  return updated
}

export async function listAllTags(env: Env): Promise<Array<{ tag: string; count: number }>> {
  const ids = await getIncidentIndex(env)
  const incidents = await Promise.all(ids.map(id => getIncident(env, id)))
  const validIncidents = incidents.filter((i): i is IncidentRecord => i !== null)

  const tagCounts: Record<string, number> = {}
  for (const incident of validIncidents) {
    for (const tag of incident.tags || []) {
      const normalizedTag = tag.toLowerCase().trim()
      tagCounts[normalizedTag] = (tagCounts[normalizedTag] || 0) + 1
    }
  }

  return Object.entries(tagCounts)
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => b.count - a.count)
}

// SLA thresholds in minutes for each severity
const SLA_THRESHOLDS: Record<IncidentSeverity, { acknowledge: number; resolve: number }> = {
  critical: { acknowledge: 15, resolve: 60 },
  high: { acknowledge: 30, resolve: 240 },
  medium: { acknowledge: 60, resolve: 480 },
  low: { acknowledge: 240, resolve: 1440 },
}

export function calculateSlaDeadline(
  severity: IncidentSeverity,
  createdAt: string
): string {
  const thresholds = SLA_THRESHOLDS[severity]
  const created = new Date(createdAt)
  const deadline = new Date(created.getTime() + thresholds.resolve * 60 * 1000)
  return deadline.toISOString()
}

export async function acknowledgeIncident(
  env: Env,
  incident: IncidentRecord,
  principal: AuthPrincipal
): Promise<IncidentRecord> {
  if (incident.status !== 'open') {
    throw new Error('Can only acknowledge open incidents')
  }

  const now = nowIso()
  const updated: IncidentRecord = {
    ...incident,
    acknowledged_by: principal.sub,
    acknowledged_at: now,
    status: 'analyzed', // Move to analyzed status after acknowledgment
    updated_at: now,
  }

  await storeIncident(env, updated)

  await publishIncidentEvent(env, updated, 'incident.acknowledged')
  await triggerWebhooks(env, 'incident.analyzed', updated)

  return updated
}

export async function escalateIncident(
  env: Env,
  incident: IncidentRecord,
  escalateToSeverity: IncidentSeverity
): Promise<IncidentRecord> {
  const severityOrder: IncidentSeverity[] = ['low', 'medium', 'high', 'critical']
  const currentIndex = severityOrder.indexOf(incident.severity)
  const escalateToIndex = severityOrder.indexOf(escalateToSeverity)

  if (escalateToIndex <= currentIndex) {
    throw new Error('Can only escalate to a higher severity')
  }

  const now = nowIso()
  const updated: IncidentRecord = {
    ...incident,
    severity: escalateToSeverity,
    escalated_from: incident.severity,
    escalated_at: now,
    sla_deadline: calculateSlaDeadline(escalateToSeverity, incident.created_at),
    updated_at: now,
  }

  await storeIncident(env, updated)

  await publishIncidentEvent(env, updated, 'incident.escalated')

  return updated
}

export async function checkSlaBreaches(env: Env): Promise<IncidentRecord[]> {
  const ids = await getIncidentIndex(env)
  const incidents = await Promise.all(ids.map(id => getIncident(env, id)))
  const openIncidents = incidents.filter((i): i is IncidentRecord =>
    i !== null && ['open', 'analyzed', 'approved'].includes(i.status)
  )

  const now = new Date()
  const breached: IncidentRecord[] = []

  for (const incident of openIncidents) {
    const deadline = incident.sla_deadline || calculateSlaDeadline(incident.severity, incident.created_at)
    if (new Date(deadline) < now) {
      breached.push(incident)
    }
  }

  return breached
}

export async function autoEscalateBreachedIncidents(env: Env): Promise<IncidentRecord[]> {
  const breached = await checkSlaBreaches(env)
  const escalated: IncidentRecord[] = []

  const severityOrder: IncidentSeverity[] = ['low', 'medium', 'high', 'critical']

  for (const incident of breached) {
    const currentIndex = severityOrder.indexOf(incident.severity)
    if (currentIndex < severityOrder.length - 1) {
      const newSeverity = severityOrder[currentIndex + 1]
      const escalatedIncident = await escalateIncident(env, incident, newSeverity)
      escalated.push(escalatedIncident)
    }
  }

  return escalated
}

export async function getIncidentSlaStatus(
  env: Env,
  incident: IncidentRecord
): Promise<{
  acknowledged: boolean
  acknowledgedWithinSla: boolean
  resolvedWithinSla: boolean
  timeToAcknowledge?: number
  timeToResolve?: number
  slaDeadline: string
  isBreached: boolean
}> {
  const deadline = incident.sla_deadline || calculateSlaDeadline(incident.severity, incident.created_at)
  const thresholds = SLA_THRESHOLDS[incident.severity]
  const created = new Date(incident.created_at)
  const now = new Date()

  const result = {
    acknowledged: !!incident.acknowledged_at,
    acknowledgedWithinSla: true,
    resolvedWithinSla: true,
    timeToAcknowledge: undefined as number | undefined,
    timeToResolve: undefined as number | undefined,
    slaDeadline: deadline,
    isBreached: false,
  }

  if (incident.acknowledged_at) {
    const acknowledged = new Date(incident.acknowledged_at)
    result.timeToAcknowledge = (acknowledged.getTime() - created.getTime()) / 1000 / 60 // minutes
    result.acknowledgedWithinSla = result.timeToAcknowledge <= thresholds.acknowledge
  }

  if (incident.status === 'resolved' && incident.updated_at) {
    const resolved = new Date(incident.updated_at)
    result.timeToResolve = (resolved.getTime() - created.getTime()) / 1000 / 60 // minutes
    result.resolvedWithinSla = result.timeToResolve <= thresholds.resolve
  }

  result.isBreached = new Date(deadline) < now && !['resolved', 'failed'].includes(incident.status)

  return result
}

export async function assignIncident(
  env: Env,
  incident: IncidentRecord,
  assigneeId: number,
  assigneeEmail?: string
): Promise<IncidentRecord> {
  const now = nowIso()
  const updated: IncidentRecord = {
    ...incident,
    assignee_id: assigneeId,
    assignee_email: assigneeEmail,
    assigned_at: now,
    updated_at: now,
  }

  await storeIncident(env, updated)

  await publishIncidentEvent(env, updated, 'incident.assigned')

  return updated
}

export async function unassignIncident(
  env: Env,
  incident: IncidentRecord
): Promise<IncidentRecord> {
  const now = nowIso()
  const updated: IncidentRecord = {
    ...incident,
    assignee_id: undefined,
    assignee_email: undefined,
    assigned_at: undefined,
    updated_at: now,
  }

  await storeIncident(env, updated)

  return updated
}

export async function listAssignedIncidents(
  env: Env,
  assigneeId: number
): Promise<IncidentRecord[]> {
  const ids = await getIncidentIndex(env)
  const incidents = await Promise.all(ids.map(id => getIncident(env, id)))
  return incidents.filter((i): i is IncidentRecord =>
    i !== null && i.assignee_id === assigneeId && !['resolved', 'failed'].includes(i.status)
  )
}
