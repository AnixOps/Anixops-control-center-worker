import type { Context } from 'hono'
import { z } from 'zod'
import type { Env, IncidentEvidence, IncidentLink } from '../types'
import { logAudit } from '../utils/audit'
import {
  addIncidentComment,
  addIncidentEvidence,
  addIncidentLink,
  addIncidentTags,
  acknowledgeIncident,
  analyzeIncident,
  approveIncident,
  assignIncident,
  bulkAnalyzeIncidents,
  bulkApproveIncidents,
  bulkDeleteIncidents,
  bulkExecuteIncidents,
  buildIncidentTimeline,
  canApproveIncident,
  canExecuteIncident,
  createAutomationRule,
  createIncident,
  createIncidentFromTemplate,
  createIncidentTemplate,
  createNotificationRule,
  createPostMortem,
  createSuppressionRule,
  deleteAutomationRule,
  deleteIncidentComment,
  deleteIncidentTemplate,
  deleteNotificationRule,
  deleteSuppressionRule,
  escalateIncident,
  executeIncident,
  executeRunbookForIncident,
  generateIncidentReport,
  getIncident,
  getIncidentActivityLog,
  getIncidentComment,
  getIncidentSlaStatus,
  getIncidentStatistics,
  getIncidentTemplate,
  getPostMortem,
  listAllTags,
  listAssignedIncidents,
  listAutomationRules,
  listIncidentComments,
  listIncidentTemplates,
  listIncidents,
  listNotificationRules,
  listSuppressionRules,
  mergeIncidents,
  removeIncidentLink,
  removeIncidentTags,
  searchIncidents,
  setIncidentTags,
  suggestRunbooks,
  toggleAutomationRule,
  toggleNotificationRule,
  toggleSuppressionRule,
  toIncidentDetail,
  toIncidentSummary,
  unassignIncident,
  updateActionItemStatus,
  updateIncidentComment,
  updateIncidentTemplate,
  updatePostMortem,
} from '../services/incidents'

const createIncidentSchema = z.object({
  title: z.string().min(1),
  source: z.string().min(1),
  summary: z.string().optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  correlation_id: z.string().optional(),
  action_type: z.enum(['scale_policy', 'restart_deployment', 'scale_deployment']).optional(),
  action_ref: z.string().optional(),
  tags: z.array(z.string().max(50)).max(10).optional(),
  evidence: z.array(z.object({
    type: z.enum(['log', 'metric', 'task', 'node', 'alert', 'service', 'manual']),
    source: z.string().min(1),
    content: z.string().min(1),
  })).optional(),
})

const listIncidentQuerySchema = z.object({
  status: z.enum(['open', 'analyzed', 'approved', 'executing', 'resolved', 'failed']).optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  action_type: z.enum(['scale_policy', 'restart_deployment', 'scale_deployment']).optional(),
  source: z.string().optional(),
  requested_via: z.enum(['jwt', 'api_key']).optional(),
  approved_by: z.coerce.number().int().optional(),
  correlation_id: z.string().optional(),
  has_action: z.enum(['true', 'false']).optional(),
  page: z.coerce.number().int().min(1).default(1),
  per_page: z.coerce.number().int().min(1).max(100).default(20),
  sort: z.enum(['created_at', 'updated_at', 'severity', 'status']).default('created_at'),
  order: z.enum(['asc', 'desc']).default('desc'),
})

async function requireIncident(c: Context<{ Bindings: Env }>) {
  const incidentId = c.req.param('id') as string
  const incident = await getIncident(c.env, incidentId)

  if (!incident) {
    return c.json({ success: false, error: 'Incident not found' }, 404)
  }

  return incident
}

export async function listIncidentsHandler(c: Context<{ Bindings: Env }>) {
  const rawQuery = listIncidentQuerySchema.parse(Object.fromEntries(new URL(c.req.url).searchParams))
  const query = {
    ...rawQuery,
    has_action: rawQuery.has_action === undefined ? undefined : rawQuery.has_action === 'true',
  }
  const incidents = await listIncidents(c.env, query)

  return c.json({
    success: true,
    data: {
      items: incidents.items.map(toIncidentSummary),
      total: incidents.total,
      page: incidents.page,
      per_page: incidents.per_page,
      total_pages: incidents.total_pages,
    },
  })
}

export async function getIncidentHandler(c: Context<{ Bindings: Env }>) {
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  return c.json({ success: true, data: toIncidentDetail(incident) })
}

export async function createIncidentHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')

  try {
    const body = createIncidentSchema.parse(await c.req.json())
    const incident = await createIncident(c.env, principal, body)

    await logAudit(c, principal.sub, 'create_incident', 'incident', {
      incident_id: incident.id,
      severity: incident.severity,
      source: incident.source,
      action_type: incident.action_type,
      action_ref: incident.action_ref,
    })

    return c.json({ success: true, data: toIncidentDetail(incident) }, 201)
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function analyzeIncidentHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  const updated = await analyzeIncident(c.env, incident)

  await logAudit(c, principal.sub, 'analyze_incident', 'incident', {
    incident_id: updated.id,
    status: updated.status,
  })

  return c.json({ success: true, data: toIncidentDetail(updated) })
}

export async function approveIncidentHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  if (!await canApproveIncident(c.env, principal, incident)) {
    return c.json({ success: false, error: 'Forbidden: approval policy denies this action' }, 403)
  }

  const updated = await approveIncident(c.env, incident, principal)

  await logAudit(c, principal.sub, 'approve_incident', 'incident', {
    incident_id: updated.id,
    approved_at: updated.approved_at,
  })

  return c.json({ success: true, data: toIncidentDetail(updated) })
}

export async function executeIncidentHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  if (!await canExecuteIncident(c.env, principal, incident)) {
    return c.json({ success: false, error: 'Forbidden: execution policy denies this action' }, 403)
  }

  try {
    const updated = await executeIncident(c.env, incident)

    await logAudit(c, principal.sub, 'execute_incident', 'incident', {
      incident_id: updated.id,
      status: updated.status,
      execution_id: updated.execution_id,
      action_type: updated.action_type,
      action_ref: updated.action_ref,
    }, updated.status === 'resolved' ? 'success' : 'failure')

    return c.json({ success: true, data: toIncidentDetail(updated) }, updated.status === 'resolved' ? 200 : 400)
  } catch (err) {
    return c.json({ success: false, error: err instanceof Error ? err.message : 'Execution failed' }, 400)
  }
}

export async function acknowledgeIncidentHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  try {
    const updated = await acknowledgeIncident(c.env, incident, principal)

    await logAudit(c, principal.sub, 'acknowledge_incident', 'incident', {
      incident_id: updated.id,
      acknowledged_at: updated.acknowledged_at,
    })

    return c.json({ success: true, data: toIncidentDetail(updated) })
  } catch (err) {
    return c.json({ success: false, error: err instanceof Error ? err.message : 'Acknowledgment failed' }, 400)
  }
}

const escalateSchema = z.object({
  severity: z.enum(['low', 'medium', 'high', 'critical']),
})

export async function escalateIncidentHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  try {
    const body = escalateSchema.parse(await c.req.json())
    const updated = await escalateIncident(c.env, incident, body.severity)

    await logAudit(c, principal.sub, 'escalate_incident', 'incident', {
      incident_id: updated.id,
      escalated_from: incident.severity,
      escalated_to: updated.severity,
      escalated_at: updated.escalated_at,
    })

    return c.json({ success: true, data: toIncidentDetail(updated) })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    return c.json({ success: false, error: err instanceof Error ? err.message : 'Escalation failed' }, 400)
  }
}

const assignSchema = z.object({
  assignee_id: z.number().int().positive(),
  assignee_email: z.string().email().optional(),
})

export async function assignIncidentHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  try {
    const body = assignSchema.parse(await c.req.json())
    const updated = await assignIncident(c.env, incident, body.assignee_id, body.assignee_email)

    await logAudit(c, principal.sub, 'assign_incident', 'incident', {
      incident_id: updated.id,
      assignee_id: body.assignee_id,
      assignee_email: body.assignee_email,
      assigned_at: updated.assigned_at,
    })

    return c.json({ success: true, data: toIncidentDetail(updated) })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    return c.json({ success: false, error: err instanceof Error ? err.message : 'Assignment failed' }, 400)
  }
}

export async function unassignIncidentHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  const updated = await unassignIncident(c.env, incident)

  await logAudit(c, principal.sub, 'unassign_incident', 'incident', {
    incident_id: updated.id,
  })

  return c.json({ success: true, data: toIncidentDetail(updated) })
}

export async function getIncidentSlaStatusHandler(c: Context<{ Bindings: Env }>) {
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  const slaStatus = await getIncidentSlaStatus(c.env, incident)
  return c.json({ success: true, data: slaStatus })
}

export async function getIncidentTimelineHandler(c: Context<{ Bindings: Env }>) {
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  const timeline = buildIncidentTimeline(incident)
  return c.json({ success: true, data: timeline })
}

const createCommentSchema = z.object({
  content: z.string().min(1).max(5000),
  visibility: z.enum(['public', 'internal']).optional(),
})

const updateCommentSchema = z.object({
  content: z.string().min(1).max(5000),
})

export async function listIncidentCommentsHandler(c: Context<{ Bindings: Env }>) {
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  const comments = await listIncidentComments(c.env, incident.id)
  return c.json({ success: true, data: comments })
}

export async function addIncidentCommentHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  try {
    const body = createCommentSchema.parse(await c.req.json())
    const comment = await addIncidentComment(c.env, incident, principal, body)

    await logAudit(c, principal.sub, 'add_incident_comment', 'incident', {
      incident_id: incident.id,
      comment_id: comment.id,
      visibility: comment.visibility,
    })

    return c.json({ success: true, data: comment }, 201)
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function updateIncidentCommentHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const commentId = c.req.param('commentId') as string

  try {
    const body = updateCommentSchema.parse(await c.req.json())
    const updated = await updateIncidentComment(c.env, commentId, principal, body.content)

    if (!updated) {
      return c.json({ success: false, error: 'Comment not found or not authorized' }, 404)
    }

    await logAudit(c, principal.sub, 'update_incident_comment', 'incident', {
      incident_id: updated.incident_id,
      comment_id: updated.id,
    })

    return c.json({ success: true, data: updated })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function deleteIncidentCommentHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const commentId = c.req.param('commentId') as string

  const deleted = await deleteIncidentComment(c.env, commentId, principal)

  if (!deleted) {
    return c.json({ success: false, error: 'Comment not found or not authorized' }, 404)
  }

  await logAudit(c, principal.sub, 'delete_incident_comment', 'incident', {
    comment_id: commentId,
  })

  return c.json({ success: true })
}

// Tag Management
const tagsSchema = z.object({
  tags: z.array(z.string().max(50)).min(1).max(10),
})

export async function listTagsHandler(c: Context<{ Bindings: Env }>) {
  const tags = await listAllTags(c.env)
  return c.json({ success: true, data: tags })
}

export async function addTagsHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  try {
    const body = tagsSchema.parse(await c.req.json())
    const updated = await addIncidentTags(c.env, incident, body.tags)

    await logAudit(c, principal.sub, 'add_incident_tags', 'incident', {
      incident_id: incident.id,
      tags: body.tags,
    })

    return c.json({ success: true, data: toIncidentDetail(updated) })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function removeTagsHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  try {
    const body = tagsSchema.parse(await c.req.json())
    const updated = await removeIncidentTags(c.env, incident, body.tags)

    await logAudit(c, principal.sub, 'remove_incident_tags', 'incident', {
      incident_id: incident.id,
      tags: body.tags,
    })

    return c.json({ success: true, data: toIncidentDetail(updated) })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function setTagsHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  try {
    const body = tagsSchema.parse(await c.req.json())
    const updated = await setIncidentTags(c.env, incident, body.tags)

    await logAudit(c, principal.sub, 'set_incident_tags', 'incident', {
      incident_id: incident.id,
      tags: body.tags,
    })

    return c.json({ success: true, data: toIncidentDetail(updated) })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

const statisticsQuerySchema = z.object({
  since: z.string().optional(),
  until: z.string().optional(),
})

export async function getIncidentStatisticsHandler(c: Context<{ Bindings: Env }>) {
  const rawQuery = Object.fromEntries(new URL(c.req.url).searchParams)
  const query = statisticsQuerySchema.parse(rawQuery)

  const stats = await getIncidentStatistics(c.env, query)
  return c.json({ success: true, data: stats })
}

const searchQuerySchema = z.object({
  q: z.string().min(2),
  status: z.string().optional(),
  severity: z.string().optional(),
  action_type: z.string().optional(),
  source: z.string().optional(),
  created_after: z.string().optional(),
  created_before: z.string().optional(),
  page: z.coerce.number().int().min(1).default(1),
  per_page: z.coerce.number().int().min(1).max(100).default(20),
})

export async function searchIncidentsHandler(c: Context<{ Bindings: Env }>) {
  const rawQuery = Object.fromEntries(new URL(c.req.url).searchParams)
  const query = searchQuerySchema.parse(rawQuery)

  const searchParams: Parameters<typeof searchIncidents>[1] = {
    query: query.q,
    page: query.page,
    per_page: query.per_page,
  }

  if (query.status) {
    searchParams.status = query.status.split(',').filter(s =>
      ['open', 'analyzed', 'approved', 'executing', 'resolved', 'failed'].includes(s)
    ) as typeof searchParams.status
  }

  if (query.severity) {
    searchParams.severity = query.severity.split(',').filter(s =>
      ['low', 'medium', 'high', 'critical'].includes(s)
    ) as typeof searchParams.severity
  }

  if (query.action_type) {
    searchParams.action_type = query.action_type.split(',').filter(s =>
      ['scale_policy', 'restart_deployment', 'scale_deployment'].includes(s)
    ) as typeof searchParams.action_type
  }

  if (query.source) {
    searchParams.source = query.source.split(',')
  }

  if (query.created_after) {
    searchParams.created_after = query.created_after
  }

  if (query.created_before) {
    searchParams.created_before = query.created_before
  }

  const results = await searchIncidents(c.env, searchParams)

  return c.json({
    success: true,
    data: {
      items: results.items.map(item => ({
        id: item.id,
        title: item.title,
        summary: item.summary,
        status: item.status,
        severity: item.severity,
        source: item.source,
        action_type: item.action_type,
        action_ref: item.action_ref,
        correlation_id: item.correlation_id,
        search_score: item.search_score,
        search_highlights: item.search_highlights,
        created_at: item.created_at,
        updated_at: item.updated_at,
      })),
      total: results.total,
      page: results.page,
      per_page: results.per_page,
      total_pages: results.total_pages,
      query: results.query,
    },
  })
}

const bulkOperationSchema = z.object({
  incident_ids: z.array(z.string().uuid()).min(1).max(50),
})

export async function bulkApproveIncidentsHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')

  try {
    const body = bulkOperationSchema.parse(await c.req.json())
    const result = await bulkApproveIncidents(c.env, principal, body.incident_ids)

    await logAudit(c, principal.sub, 'bulk_approve_incidents', 'incident', {
      total: result.total,
      successful: result.successful.length,
      failed: result.failed.length,
    })

    return c.json({ success: true, data: result })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function bulkExecuteIncidentsHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')

  try {
    const body = bulkOperationSchema.parse(await c.req.json())
    const result = await bulkExecuteIncidents(c.env, principal, body.incident_ids)

    await logAudit(c, principal.sub, 'bulk_execute_incidents', 'incident', {
      total: result.total,
      successful: result.successful.length,
      failed: result.failed.length,
    })

    return c.json({ success: true, data: result })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function bulkAnalyzeIncidentsHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')

  try {
    const body = bulkOperationSchema.parse(await c.req.json())
    const result = await bulkAnalyzeIncidents(c.env, body.incident_ids)

    await logAudit(c, principal.sub, 'bulk_analyze_incidents', 'incident', {
      total: result.total,
      successful: result.successful.length,
      failed: result.failed.length,
    })

    return c.json({ success: true, data: result })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function bulkDeleteIncidentsHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')

  try {
    const body = bulkOperationSchema.parse(await c.req.json())
    const result = await bulkDeleteIncidents(c.env, body.incident_ids)

    await logAudit(c, principal.sub, 'bulk_delete_incidents', 'incident', {
      total: result.total,
      successful: result.successful.length,
      failed: result.failed.length,
    })

    return c.json({ success: true, data: result })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

// Suppression Rules
const createSuppressionRuleSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  conditions: z.object({
    severity: z.array(z.enum(['low', 'medium', 'high', 'critical'])).optional(),
    source: z.array(z.string()).optional(),
    action_type: z.array(z.enum(['scale_policy', 'restart_deployment', 'scale_deployment'])).optional(),
    title_pattern: z.string().optional(),
    correlation_id_pattern: z.string().optional(),
  }),
  duration_minutes: z.number().int().min(1).max(10080), // Max 1 week
})

export async function listSuppressionRulesHandler(c: Context<{ Bindings: Env }>) {
  const rules = await listSuppressionRules(c.env)
  return c.json({ success: true, data: rules })
}

export async function createSuppressionRuleHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')

  try {
    const body = createSuppressionRuleSchema.parse(await c.req.json())
    const rule = await createSuppressionRule(c.env, principal, {
      name: body.name,
      description: body.description,
      conditions: body.conditions,
      duration_minutes: body.duration_minutes,
    })

    await logAudit(c, principal.sub, 'create_suppression_rule', 'incident', {
      rule_id: rule.id,
      rule_name: rule.name,
      duration_minutes: rule.duration_minutes,
    })

    return c.json({ success: true, data: rule }, 201)
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function deleteSuppressionRuleHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const ruleId = c.req.param('ruleId') as string

  const deleted = await deleteSuppressionRule(c.env, ruleId)

  if (!deleted) {
    return c.json({ success: false, error: 'Suppression rule not found' }, 404)
  }

  await logAudit(c, principal.sub, 'delete_suppression_rule', 'incident', {
    rule_id: ruleId,
  })

  return c.json({ success: true })
}

export async function toggleSuppressionRuleHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const ruleId = c.req.param('ruleId') as string

  try {
    const body = z.object({ enabled: z.boolean() }).parse(await c.req.json())
    const rule = await toggleSuppressionRule(c.env, ruleId, body.enabled)

    if (!rule) {
      return c.json({ success: false, error: 'Suppression rule not found' }, 404)
    }

    await logAudit(c, principal.sub, 'toggle_suppression_rule', 'incident', {
      rule_id: ruleId,
      enabled: body.enabled,
    })

    return c.json({ success: true, data: rule })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

// Incident Merging
const mergeSchema = z.object({
  primary_id: z.string().uuid(),
  incident_ids: z.array(z.string().uuid()).min(1).max(10),
})

export async function mergeIncidentsHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')

  try {
    const body = mergeSchema.parse(await c.req.json())

    // Ensure primary is in the list
    if (!body.incident_ids.includes(body.primary_id)) {
      body.incident_ids.push(body.primary_id)
    }

    const result = await mergeIncidents(c.env, body.primary_id, body.incident_ids)

    await logAudit(c, principal.sub, 'merge_incidents', 'incident', {
      primary_id: body.primary_id,
      merged_ids: result.merged.map(i => i.id),
      merged_count: result.merged_count,
    })

    return c.json({
      success: true,
      data: {
        primary: toIncidentDetail(result.primary),
        merged_count: result.merged_count,
        merged_ids: result.merged.map(i => i.id),
      },
    })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    return c.json({ success: false, error: err instanceof Error ? err.message : 'Merge failed' }, 400)
  }
}

// Notification Rules
const createNotificationRuleSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  conditions: z.object({
    severity: z.array(z.enum(['low', 'medium', 'high', 'critical'])).optional(),
    source: z.array(z.string()).optional(),
    action_type: z.array(z.enum(['scale_policy', 'restart_deployment', 'scale_deployment'])).optional(),
    status: z.array(z.enum(['open', 'analyzed', 'approved', 'executing', 'resolved', 'failed'])).optional(),
    tags: z.array(z.string()).optional(),
  }),
  channels: z.array(z.enum(['email', 'webhook', 'slack'])).min(1),
  recipients: z.array(z.string()).min(1),
  template: z.string().optional(),
})

export async function listNotificationRulesHandler(c: Context<{ Bindings: Env }>) {
  const rules = await listNotificationRules(c.env)
  return c.json({ success: true, data: rules })
}

export async function createNotificationRuleHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')

  try {
    const body = createNotificationRuleSchema.parse(await c.req.json())
    const rule = await createNotificationRule(c.env, principal, {
      name: body.name,
      description: body.description,
      conditions: body.conditions,
      channels: body.channels,
      recipients: body.recipients,
      template: body.template,
    })

    await logAudit(c, principal.sub, 'create_notification_rule', 'incident', {
      rule_id: rule.id,
      rule_name: rule.name,
      channels: rule.channels,
    })

    return c.json({ success: true, data: rule }, 201)
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function deleteNotificationRuleHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const ruleId = c.req.param('ruleId') as string

  const deleted = await deleteNotificationRule(c.env, ruleId)

  if (!deleted) {
    return c.json({ success: false, error: 'Notification rule not found' }, 404)
  }

  await logAudit(c, principal.sub, 'delete_notification_rule', 'incident', {
    rule_id: ruleId,
  })

  return c.json({ success: true })
}

export async function toggleNotificationRuleHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const ruleId = c.req.param('ruleId') as string

  try {
    const body = z.object({ enabled: z.boolean() }).parse(await c.req.json())
    const rule = await toggleNotificationRule(c.env, ruleId, body.enabled)

    if (!rule) {
      return c.json({ success: false, error: 'Notification rule not found' }, 404)
    }

    await logAudit(c, principal.sub, 'toggle_notification_rule', 'incident', {
      rule_id: ruleId,
      enabled: body.enabled,
    })

    return c.json({ success: true, data: rule })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

// Reports
const reportQuerySchema = z.object({
  start_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  end_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
})

export async function getIncidentReportHandler(c: Context<{ Bindings: Env }>) {
  const rawQuery = Object.fromEntries(new URL(c.req.url).searchParams)
  const query = reportQuerySchema.parse(rawQuery)

  const report = await generateIncidentReport(c.env, query.start_date, query.end_date)
  return c.json({ success: true, data: report })
}

// Link Management
const linkSchema = z.object({
  kind: z.enum(['task', 'node', 'scaling_policy', 'deployment', 'runbook', 'alert', 'playbook']),
  id: z.string().min(1),
  name: z.string().optional(),
  href: z.string().optional(),
  relationship: z.enum(['caused_by', 'related_to', 'resolves', 'investigates']).optional(),
})

export async function addIncidentLinkHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  try {
    const body = linkSchema.parse(await c.req.json())
    const updated = await addIncidentLink(c.env, incident, body as IncidentLink)

    await logAudit(c, principal.sub, 'add_incident_link', 'incident', {
      incident_id: incident.id,
      link_kind: body.kind,
      link_id: body.id,
    })

    return c.json({ success: true, data: toIncidentDetail(updated) })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function removeIncidentLinkHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  const linkKind = c.req.param('linkKind') as IncidentLink['kind']
  const linkId = c.req.param('linkId') as string

  const updated = await removeIncidentLink(c.env, incident, linkKind, linkId)

  await logAudit(c, principal.sub, 'remove_incident_link', 'incident', {
    incident_id: incident.id,
    link_kind: linkKind,
    link_id: linkId,
  })

  return c.json({ success: true, data: toIncidentDetail(updated) })
}

// Evidence Management
const evidenceSchema = z.object({
  type: z.enum(['log', 'metric', 'task', 'node', 'alert', 'service', 'manual']),
  source: z.string().min(1),
  content: z.string().min(1),
})

export async function addIncidentEvidenceHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  try {
    const body = evidenceSchema.parse(await c.req.json())
    const updated = await addIncidentEvidence(c.env, incident, body as IncidentEvidence)

    await logAudit(c, principal.sub, 'add_incident_evidence', 'incident', {
      incident_id: incident.id,
      evidence_type: body.type,
      evidence_source: body.source,
    })

    return c.json({ success: true, data: toIncidentDetail(updated) })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

// Activity Log
export async function getIncidentActivityLogHandler(c: Context<{ Bindings: Env }>) {
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  const logs = await getIncidentActivityLog(c.env, incident.id)
  return c.json({ success: true, data: logs })
}

// Runbook Suggestions
export async function getRunbookSuggestionsHandler(c: Context<{ Bindings: Env }>) {
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  const suggestions = await suggestRunbooks(c.env, incident)
  return c.json({ success: true, data: suggestions })
}

export async function executeRunbookHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incident = await requireIncident(c)
  if (incident instanceof Response) {
    return incident
  }

  try {
    const body = z.object({ playbook_id: z.number().int().positive() }).parse(await c.req.json())
    const result = await executeRunbookForIncident(c.env, incident, body.playbook_id, principal)

    await logAudit(c, principal.sub, 'execute_runbook_for_incident', 'incident', {
      incident_id: incident.id,
      playbook_id: body.playbook_id,
      task_id: result.task_id,
    })

    return c.json({ success: true, data: result })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

// ==================== Templates ====================

const createTemplateSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  category: z.string().max(50).optional(),
  title_template: z.string().min(1).max(200),
  summary_template: z.string().max(1000).optional(),
  default_severity: z.enum(['low', 'medium', 'high', 'critical']),
  default_source: z.string().min(1),
  default_action_type: z.enum(['scale_policy', 'restart_deployment', 'scale_deployment']).optional(),
  default_action_ref: z.string().optional(),
  default_tags: z.array(z.string().max(50)).default([]),
  evidence_templates: z.array(z.object({
    type: z.enum(['log', 'metric', 'task', 'node', 'alert', 'service', 'manual']),
    source_template: z.string(),
    content_template: z.string().optional(),
  })).default([]),
})

export async function listTemplatesHandler(c: Context<{ Bindings: Env }>) {
  const templates = await listIncidentTemplates(c.env)
  return c.json({ success: true, data: templates })
}

export async function getTemplateHandler(c: Context<{ Bindings: Env }>) {
  const templateId = c.req.param('templateId') as string
  const template = await getIncidentTemplate(c.env, templateId)

  if (!template) {
    return c.json({ success: false, error: 'Template not found' }, 404)
  }

  return c.json({ success: true, data: template })
}

export async function createTemplateHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')

  try {
    const body = createTemplateSchema.parse(await c.req.json())
    const template = await createIncidentTemplate(c.env, principal, {
      name: body.name,
      description: body.description,
      category: body.category,
      title_template: body.title_template,
      summary_template: body.summary_template,
      default_severity: body.default_severity,
      default_source: body.default_source,
      default_action_type: body.default_action_type,
      default_action_ref: body.default_action_ref,
      default_tags: body.default_tags,
      evidence_templates: body.evidence_templates,
    })

    await logAudit(c, principal.sub, 'create_incident_template', 'incident', {
      template_id: template.id,
      template_name: template.name,
    })

    return c.json({ success: true, data: template }, 201)
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function updateTemplateHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const templateId = c.req.param('templateId') as string

  try {
    const body = createTemplateSchema.partial().parse(await c.req.json())
    const template = await updateIncidentTemplate(c.env, templateId, body)

    if (!template) {
      return c.json({ success: false, error: 'Template not found' }, 404)
    }

    await logAudit(c, principal.sub, 'update_incident_template', 'incident', {
      template_id: templateId,
    })

    return c.json({ success: true, data: template })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function deleteTemplateHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const templateId = c.req.param('templateId') as string

  const deleted = await deleteIncidentTemplate(c.env, templateId)

  if (!deleted) {
    return c.json({ success: false, error: 'Template not found' }, 404)
  }

  await logAudit(c, principal.sub, 'delete_incident_template', 'incident', {
    template_id: templateId,
  })

  return c.json({ success: true })
}

export async function createFromTemplateHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const templateId = c.req.param('templateId') as string

  try {
    const body = z.object({ variables: z.record(z.string()).optional() }).parse(await c.req.json())
    const incident = await createIncidentFromTemplate(c.env, principal, templateId, body.variables || {})

    await logAudit(c, principal.sub, 'create_incident_from_template', 'incident', {
      template_id: templateId,
      incident_id: incident.id,
    })

    return c.json({ success: true, data: toIncidentDetail(incident) }, 201)
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    return c.json({ success: false, error: err instanceof Error ? err.message : 'Failed to create incident' }, 400)
  }
}

// ==================== Automation Rules ====================

const createActionSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('assign'), assignee_id: z.number().int().positive() }),
  z.object({ type: z.literal('escalate'), target_severity: z.enum(['low', 'medium', 'high', 'critical']) }),
  z.object({ type: z.literal('add_tags'), tags: z.array(z.string()).min(1) }),
  z.object({ type: z.literal('notify'), channels: z.array(z.string()).min(1), recipients: z.array(z.string()).min(1) }),
  z.object({ type: z.literal('execute_runbook'), playbook_id: z.number().int().positive() }),
  z.object({ type: z.literal('set_sla'), minutes: z.number().int().min(1).max(10080) }),
  z.object({ type: z.literal('add_comment'), content: z.string().min(1).max(5000) }),
])

const createAutomationRuleSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  enabled: z.boolean().default(true),
  trigger: z.enum(['incident.created', 'incident.acknowledged', 'incident.escalated', 'incident.analyzed', 'incident.approved', 'incident.resolved', 'incident.failed', 'sla_breach', 'duplicate_detected']),
  conditions: z.object({
    severity: z.array(z.enum(['low', 'medium', 'high', 'critical'])).optional(),
    source: z.array(z.string()).optional(),
    action_type: z.array(z.enum(['scale_policy', 'restart_deployment', 'scale_deployment'])).optional(),
    tags: z.array(z.string()).optional(),
    time_range: z.object({ start_hour: z.number().min(0).max(23), end_hour: z.number().min(1).max(24) }).optional(),
  }),
  actions: z.array(createActionSchema).min(1),
  priority: z.number().int().min(1).max(100).default(50),
})

export async function listAutomationRulesHandler(c: Context<{ Bindings: Env }>) {
  const rules = await listAutomationRules(c.env)
  return c.json({ success: true, data: rules })
}

export async function createAutomationRuleHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')

  try {
    const body = createAutomationRuleSchema.parse(await c.req.json())
    const rule = await createAutomationRule(c.env, principal, {
      name: body.name,
      description: body.description,
      enabled: body.enabled,
      trigger: body.trigger,
      conditions: body.conditions,
      actions: body.actions as import('../types').AutomationAction[],
      priority: body.priority,
    })

    await logAudit(c, principal.sub, 'create_automation_rule', 'incident', {
      rule_id: rule.id,
      rule_name: rule.name,
      trigger: rule.trigger,
    })

    return c.json({ success: true, data: rule }, 201)
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function deleteAutomationRuleHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const ruleId = c.req.param('ruleId') as string

  const deleted = await deleteAutomationRule(c.env, ruleId)

  if (!deleted) {
    return c.json({ success: false, error: 'Automation rule not found' }, 404)
  }

  await logAudit(c, principal.sub, 'delete_automation_rule', 'incident', {
    rule_id: ruleId,
  })

  return c.json({ success: true })
}

export async function toggleAutomationRuleHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const ruleId = c.req.param('ruleId') as string

  try {
    const body = z.object({ enabled: z.boolean() }).parse(await c.req.json())
    const rule = await toggleAutomationRule(c.env, ruleId, body.enabled)

    if (!rule) {
      return c.json({ success: false, error: 'Automation rule not found' }, 404)
    }

    await logAudit(c, principal.sub, 'toggle_automation_rule', 'incident', {
      rule_id: ruleId,
      enabled: body.enabled,
    })

    return c.json({ success: true, data: rule })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

// ==================== Post-Mortems ====================

const createPostMortemSchema = z.object({
  title: z.string().min(1).max(200),
  summary: z.string().min(1).max(5000),
  timeline: z.array(z.object({
    timestamp: z.string(),
    event: z.string(),
    details: z.string().optional(),
  })),
  root_cause: z.string().min(1).max(5000),
  contributing_factors: z.array(z.string()),
  impact: z.object({
    users_affected: z.number().int().optional(),
    duration_minutes: z.number().int().min(1),
    services_affected: z.array(z.string()),
  }),
  resolution: z.string().min(1).max(5000),
  lessons_learned: z.array(z.string()),
  action_items: z.array(z.object({
    id: z.string(),
    description: z.string(),
    owner: z.string().optional(),
    status: z.enum(['open', 'in_progress', 'completed']),
    due_date: z.string().optional(),
  })),
})

export async function getPostMortemHandler(c: Context<{ Bindings: Env }>) {
  const incidentId = c.req.param('id') as string
  const postMortem = await getPostMortem(c.env, incidentId)

  if (!postMortem) {
    return c.json({ success: false, error: 'Post-mortem not found' }, 404)
  }

  return c.json({ success: true, data: postMortem })
}

export async function createPostMortemHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incidentId = c.req.param('id') as string

  try {
    const body = createPostMortemSchema.parse(await c.req.json())
    const postMortem = await createPostMortem(c.env, principal, incidentId, {
      title: body.title,
      summary: body.summary,
      timeline: body.timeline,
      root_cause: body.root_cause,
      contributing_factors: body.contributing_factors,
      impact: body.impact,
      resolution: body.resolution,
      lessons_learned: body.lessons_learned,
      action_items: body.action_items,
    })

    await logAudit(c, principal.sub, 'create_postmortem', 'incident', {
      incident_id: incidentId,
      postmortem_id: postMortem.id,
      title: postMortem.title,
    })

    return c.json({ success: true, data: postMortem }, 201)
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    return c.json({ success: false, error: err instanceof Error ? err.message : 'Failed to create post-mortem' }, 400)
  }
}

export async function updatePostMortemHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incidentId = c.req.param('id') as string

  try {
    const body = createPostMortemSchema.partial().parse(await c.req.json())
    const postMortem = await updatePostMortem(c.env, incidentId, body)

    if (!postMortem) {
      return c.json({ success: false, error: 'Post-mortem not found' }, 404)
    }

    await logAudit(c, principal.sub, 'update_postmortem', 'incident', {
      incident_id: incidentId,
    })

    return c.json({ success: true, data: postMortem })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}

export async function updateActionItemHandler(c: Context<{ Bindings: Env }>) {
  const principal = c.get('user')
  const incidentId = c.req.param('id') as string
  const actionItemId = c.req.param('actionItemId') as string

  try {
    const body = z.object({ status: z.enum(['open', 'in_progress', 'completed']) }).parse(await c.req.json())
    const postMortem = await updateActionItemStatus(c.env, incidentId, actionItemId, body.status)

    if (!postMortem) {
      return c.json({ success: false, error: 'Post-mortem or action item not found' }, 404)
    }

    await logAudit(c, principal.sub, 'update_action_item', 'incident', {
      incident_id: incidentId,
      action_item_id: actionItemId,
      status: body.status,
    })

    return c.json({ success: true, data: postMortem })
  } catch (err) {
    if (err instanceof z.ZodError) {
      return c.json({ success: false, error: 'Validation error', details: err.errors }, 400)
    }
    throw err
  }
}
