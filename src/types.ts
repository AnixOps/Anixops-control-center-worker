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

  // Vectorize 向量数据库
  VECTORIZE: VectorizeIndex

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
    user: JWTPayload
  }
}