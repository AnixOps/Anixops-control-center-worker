import type { Context } from 'hono'
import { z } from 'zod'
import type { Env } from '../types'
import { logAudit } from '../utils/audit'
import {
  addIncidentComment,
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
  createIncident,
  deleteIncidentComment,
  escalateIncident,
  executeIncident,
  getIncident,
  getIncidentComment,
  getIncidentSlaStatus,
  getIncidentStatistics,
  listAllTags,
  listIncidentComments,
  listIncidents,
  removeIncidentTags,
  searchIncidents,
  setIncidentTags,
  toIncidentDetail,
  toIncidentSummary,
  unassignIncident,
  updateIncidentComment,
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
