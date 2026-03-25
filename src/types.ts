// Cloudflare Workers 环境类型定义

export interface Env {
  // 环境变量
  ENVIRONMENT: 'development' | 'production'
  JWT_SECRET: string
  JWT_EXPIRE: string
  API_KEY_SALT: string
  KUBERNETES_API_SERVER?: string
  KUBERNETES_NAMESPACE?: string

  // D1 数据库
  DB: D1Database

  // KV 命名空间
  KV: KVNamespace

  // R2 存储桶
  R2: R2Bucket

  // Workers AI
  AI: Ai

  // Vectorize 向量数据库 (可选 - 需要先创建索引)
  VECTORIZE?: VectorizeIndex

  // Durable Objects - 暂时禁用
  // WEBSOCKET_SERVER: DurableObjectNamespace
}

// 用户类型
export interface User {
  id: number
  email: string
  password_hash?: string
  role: 'admin' | 'operator' | 'viewer'
  auth_provider: 'local' | 'github' | 'google' | 'cloudflare'
  enabled: boolean
  last_login_at?: string
  created_at: string
  updated_at: string
}

// JWT Payload
export interface JWTPayload {
  sub: number
  email: string
  role: string
  iat: number
  exp: number
}

export interface AuthPrincipal extends JWTPayload {
  kind: 'user' | 'api_key'
  auth_method: 'jwt' | 'api_key'
  token_id?: number
  token_name?: string
}

// 节点类型
export interface Node {
  id: number
  name: string
  host: string
  port: number
  status: 'online' | 'offline' | 'maintenance'
  last_seen?: string
  config?: string
  agent_id?: string
  agent_secret?: string
  agent_version?: string
  os?: string
  arch?: string
  cpu_count?: number
  memory_gb?: number
  disk_gb?: number
  created_at: string
  updated_at: string
}

// Playbook 类型
export interface Playbook {
  id: number
  name: string
  storage_key: string
  description?: string
  category?: string
  source?: string
  github_repo?: string
  github_path?: string
  version?: string
  variables?: string
  author?: string
  tags?: string
  created_at: string
  updated_at: string
}

// 任务类型
export interface Task {
  id: number
  task_id: string
  playbook_id: number
  playbook_name: string
  status: 'pending' | 'running' | 'success' | 'failed' | 'cancelled'
  trigger_type: 'manual' | 'scheduled' | 'webhook' | 'api'
  triggered_by?: number
  target_nodes?: string
  variables?: string
  result?: string
  error?: string
  started_at?: string
  completed_at?: string
  created_at: string
}

// 任务日志类型
export interface TaskLog {
  id: number
  task_id: string
  node_id?: number
  node_name?: string
  level: 'debug' | 'info' | 'warning' | 'error'
  message: string
  metadata?: string
  created_at: string
}

// 调度类型
export interface Schedule {
  id: number
  name: string
  playbook_id: number
  playbook_name: string
  cron: string
  timezone?: string
  target_nodes?: string
  variables?: string
  enabled: boolean
  last_run?: string
  next_run?: string
  last_task_id?: string
  created_by?: number
  created_at: string
  updated_at: string
}

// 节点组类型
export interface NodeGroup {
  id: number
  name: string
  description?: string
  parent_id?: number
  created_at: string
}

// 插件类型
export interface Plugin {
  id: number
  name: string
  display_name?: string
  version?: string
  description?: string
  author?: string
  type?: string
  enabled: boolean
  config?: string
  permissions?: string
  installed_at: string
  updated_at?: string
}

// 通知类型
export interface Notification {
  id: number
  user_id: number
  type: 'info' | 'success' | 'warning' | 'error' | 'task' | 'system'
  title: string
  message?: string
  resource_type?: string
  resource_id?: string
  read: boolean
  action_url?: string
  created_at: string
}

// 审计日志类型
export interface AuditLog {
  id: number
  user_id?: number
  action: string
  resource?: string
  ip?: string
  user_agent?: string
  details?: string
  created_at: string
}

// Incident workflow types
export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical'
export type IncidentStatus = 'open' | 'analyzed' | 'approved' | 'executing' | 'resolved' | 'failed'
export type IncidentActionType = 'scale_policy' | 'restart_deployment' | 'scale_deployment'

export interface IncidentEvidence {
  type: 'log' | 'metric' | 'task' | 'node' | 'alert' | 'service' | 'manual'
  source: string
  content: string
}

export interface IncidentRecommendation {
  id: string
  title: string
  description: string
  action_type?: IncidentActionType
  action_ref?: string
  confidence?: number
}

export interface IncidentLink {
  kind: 'task' | 'node' | 'scaling_policy' | 'deployment'
  id: string
  name?: string
  href?: string
}

export interface IncidentExecutionResult {
  backend: 'autoscaling' | 'kubernetes'
  success: boolean
  message?: string
  operation?: string
  target?: {
    kind: 'scaling_policy' | 'deployment'
    id: string
    name?: string
    namespace?: string
  }
  details?: Record<string, unknown>
}

export interface IncidentSummary {
  id: string
  title: string
  summary?: string
  status: IncidentStatus
  severity: IncidentSeverity
  source: string
  requested_via: 'jwt' | 'api_key'
  action_type?: IncidentActionType
  action_ref?: string
  approved_by?: number
  correlation_id: string
  links?: IncidentLink[]
  tags: string[]
  created_at: string
  updated_at: string
}

export interface IncidentDetail extends IncidentSummary {
  requested_by: number
  requested_by_email?: string
  approved_at?: string
  execution_id?: string
  evidence: IncidentEvidence[]
  recommendations: IncidentRecommendation[]
  analysis?: Record<string, unknown>
  execution_result?: IncidentExecutionResult
  acknowledged_by?: number
  acknowledged_at?: string
  escalated_from?: string
  escalated_at?: string
  sla_deadline?: string
  assignee_id?: number
  assignee_email?: string
  assigned_at?: string
}

export interface IncidentRecord {
  id: string
  title: string
  summary?: string
  status: IncidentStatus
  severity: IncidentSeverity
  source: string
  correlation_id: string
  requested_by: number
  requested_by_email?: string
  requested_via: 'jwt' | 'api_key'
  approved_by?: number
  approved_at?: string
  execution_id?: string
  action_type?: IncidentActionType
  action_ref?: string
  evidence: IncidentEvidence[]
  recommendations: IncidentRecommendation[]
  links?: IncidentLink[]
  analysis?: Record<string, unknown>
  execution_result?: IncidentExecutionResult
  tags: string[]
  acknowledged_by?: number
  acknowledged_at?: string
  escalated_from?: string
  escalated_at?: string
  sla_deadline?: string
  assignee_id?: number
  assignee_email?: string
  assigned_at?: string
  duplicate_of?: string
  duplicate_count?: number
  suppressed_by?: SuppressionMatch
  created_at: string
  updated_at: string
}

export type IncidentTimelineEventType =
  | 'created'
  | 'acknowledged'
  | 'escalated'
  | 'assigned'
  | 'merged'
  | 'analyzed'
  | 'approved'
  | 'executing'
  | 'resolved'
  | 'failed'
  | 'evidence_added'
  | 'comment'
  | 'severity_upgraded'

export interface IncidentTimelineEvent {
  id: string
  incident_id: string
  type: IncidentTimelineEventType
  timestamp: string
  actor?: {
    user_id: number
    email?: string
    role?: string
  }
  summary: string
  details?: Record<string, unknown>
  metadata?: Record<string, unknown>
}

export interface IncidentTimeline {
  incident_id: string
  correlation_id: string
  events: IncidentTimelineEvent[]
  total_events: number
}

// Incident Comment types
export interface IncidentComment {
  id: string
  incident_id: string
  author_id: number
  author_email?: string
  author_role?: string
  content: string
  visibility: 'public' | 'internal'
  created_at: string
  updated_at: string
}

export interface IncidentCommentInput {
  content: string
  visibility?: 'public' | 'internal'
}

// Governance Policy types
export interface GovernancePolicyRule {
  id: string
  name: string
  description?: string
  enabled: boolean
  conditions: {
    severity?: IncidentSeverity[]
    action_types?: IncidentActionType[]
    sources?: string[]
  }
  effect: 'allow' | 'deny'
  principals: {
    roles?: ('admin' | 'operator' | 'viewer')[]
    user_ids?: number[]
  }
  priority: number
  created_at: string
  updated_at: string
}

export interface GovernancePolicy {
  id: string
  name: string
  description?: string
  version: number
  enabled: boolean
  default_effect: 'allow' | 'deny'
  rules: GovernancePolicyRule[]
  created_by: number
  created_at: string
  updated_at: string
}

export interface GovernanceEvaluation {
  allowed: boolean
  matched_rules: string[]
  evaluation_time: string
  policy_id: string
  policy_version: number
}

// Webhook types
export type WebhookEventType =
  | 'incident.created'
  | 'incident.acknowledged'
  | 'incident.escalated'
  | 'incident.assigned'
  | 'incident.analyzed'
  | 'incident.approved'
  | 'incident.executing'
  | 'incident.resolved'
  | 'incident.failed'

export interface WebhookEndpoint {
  id: string
  name: string
  url: string
  secret?: string
  events: WebhookEventType[]
  enabled: boolean
  headers?: Record<string, string>
  created_by: number
  created_at: string
  updated_at: string
}

export interface WebhookDelivery {
  id: string
  webhook_id: string
  event_type: WebhookEventType
  payload: Record<string, unknown>
  response_status?: number
  response_body?: string
  delivered_at?: string
  attempts: number
  last_attempt_at?: string
  success: boolean
  created_at: string
}

// Suppression Rule types
export interface SuppressionRule {
  id: string
  name: string
  description?: string
  enabled: boolean
  conditions: {
    severity?: IncidentSeverity[]
    source?: string[]
    action_type?: IncidentActionType[]
    title_pattern?: string
    correlation_id_pattern?: string
  }
  duration_minutes: number
  created_by: number
  created_at: string
  updated_at: string
  expires_at?: string
}

export interface SuppressionMatch {
  rule_id: string
  rule_name: string
  matched_at: string
  expires_at: string
}

// Deduplication config
export interface DeduplicationConfig {
  window_minutes: number
  max_duplicates: number
  group_by: ('correlation_id' | 'source' | 'title')[]
}

// Notification Rule types for incidents
export interface NotificationRule {
  id: string
  name: string
  description?: string
  enabled: boolean
  conditions: {
    severity?: IncidentSeverity[]
    source?: string[]
    action_type?: IncidentActionType[]
    status?: IncidentStatus[]
    tags?: string[]
  }
  channels: ('email' | 'webhook' | 'slack')[]
  recipients: string[]
  template?: string
  created_by: number
  created_at: string
  updated_at: string
}

// Incident Report types
export interface IncidentTrend {
  date: string
  total: number
  by_severity: Record<IncidentSeverity, number>
  by_status: Record<IncidentStatus, number>
  resolved_count: number
  avg_resolution_time_minutes: number
}

export interface IncidentReport {
  period: {
    start: string
    end: string
  }
  summary: {
    total_incidents: number
    open_incidents: number
    resolved_incidents: number
    avg_resolution_time_minutes: number
    sla_breach_count: number
    sla_compliance_rate: number
  }
  by_severity: Record<IncidentSeverity, { count: number; percentage: number }>
  by_status: Record<IncidentStatus, { count: number; percentage: number }>
  by_source: Array<{ source: string; count: number; percentage: number }>
  by_action_type: Array<{ action_type: string; count: number; success_rate: number }>
  trends: IncidentTrend[]
  top_tags: Array<{ tag: string; count: number }>
  top_sources: Array<{ source: string; count: number }>
  mttr_by_severity: Record<IncidentSeverity, number>
}

// Realtime event types
export type RealtimeScope = 'global' | 'tenant' | 'user' | 'node' | 'task' | 'audit' | 'incident' | 'system'

export interface RealtimeActor {
  user_id: number
  email: string
  role: string
}

export interface RealtimeResource {
  kind: 'node' | 'task' | 'notification' | 'audit' | 'agent' | 'incident' | 'system' | 'user'
  id: string | number
  name?: string
}

export interface RealtimeEvent<T = unknown> {
  id: string
  type: string
  scope: RealtimeScope
  channels: string[]
  payload: T
  timestamp: string
  version: number
  tenant_id?: number
  user_id?: number
  resource?: RealtimeResource
  actor?: RealtimeActor
  correlation_id?: string
}

// API 响应类型
export interface ApiResponse<T = unknown> {
  success: boolean
  data?: T
  error?: string
  message?: string
}

// 分页响应
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

// Hono 上下文变量
declare module 'hono' {
  interface ContextVariableMap {
    user: AuthPrincipal
  }
}