/**
 * Test setup file
 * Configures test environment with mocks for Cloudflare Workers
 */

import { beforeAll, afterAll, vi } from 'vitest'

// Mock KV Namespace
export function createMockKV(): KVNamespace {
  const store = new Map<string, { value: string; expiration?: number }>()

  return {
    get: vi.fn(async (key: string, options?: any) => {
      const item = store.get(key)
      if (!item) return null
      // Support both `kv.get(key, 'json')` and `kv.get(key, { type: 'json' })`
      const isJson = options === 'json' || options?.type === 'json'
      if (isJson) {
        try {
          return JSON.parse(item.value)
        } catch {
          return null
        }
      }
      return item.value
    }) as any,

    put: vi.fn(async (key: string, value: string, options?: any) => {
      store.set(key, { value, expiration: options?.expirationTtl })
    }) as any,

    delete: vi.fn(async (key: string) => {
      store.delete(key)
    }) as any,

    list: vi.fn(async () => ({
      keys: Array.from(store.keys()).map(name => ({ name })),
      list_complete: true,
    })) as any,

    getWithMetadata: vi.fn(async (key: string) => {
      const item = store.get(key)
      if (!item) return { value: null, metadata: null }
      return { value: item.value, metadata: null }
    }) as any,
  }
}

// Mock R2 Bucket
export function createMockR2(): R2Bucket {
  const store = new Map<string, { body: string; metadata?: any }>()

  return {
    get: vi.fn(async (key: string) => {
      const item = store.get(key)
      if (!item) return null
      return {
        key,
        body: item.body,
        size: item.body.length,
        text: async () => item.body,
        json: async () => JSON.parse(item.body),
        arrayBuffer: async () => new TextEncoder().encode(item.body).buffer,
      } as any
    }) as any,

    put: vi.fn(async (key: string, value: any, options?: any) => {
      const body = typeof value === 'string' ? value : JSON.stringify(value)
      store.set(key, { body, metadata: options?.customMetadata })
      return { key }
    }) as any,

    delete: vi.fn(async (key: string) => {
      store.delete(key)
    }) as any,

    list: vi.fn(async (options?: any) => ({
      objects: Array.from(store.entries())
        .filter(([key]) => !options?.prefix || key.startsWith(options.prefix))
        .map(([key, item]) => ({
          key,
          size: item.body.length,
          uploaded: new Date(),
        })),
      delimitedPrefixes: [],
    })) as any,

    head: vi.fn(async (key: string) => {
      const item = store.get(key)
      if (!item) return null
      return { key, size: item.body.length }
    }) as any,

    createMultipartUpload: vi.fn(async () => ({ uploadId: 'mock' })) as any,
    resumeMultipartUpload: vi.fn(async () => ({ uploadId: 'mock' })) as any,
  }
}

// Mock D1 Database
export function createMockD1(): D1Database {
  // In-memory storage that persists during test
  const users: any[] = []
  const nodes: any[] = []
  const playbooks: any[] = []
  const tasks: any[] = []
  const sessions: any[] = []
  const auditLogs: any[] = []
  const notifications: any[] = []
  const userMfa: any[] = []
  const tenants: any[] = []
  const tenantMembers: any[] = []
  const roles: any[] = []
  const permissions: any[] = []
  const tenantInvitations: any[] = []
  const taskLogs: any[] = []
  let idCounter = 1

  return {
    prepare: vi.fn((sql: string) => {
      const sqlLower = sql.toLowerCase()
      return {
        bind: vi.fn(function(this: any, ...args: any[]) {
          this._bindings = args
          this._sql = sql
          this._sqlLower = sqlLower
          return this
        }),
        first: vi.fn(async function(this: any) {
          const sqlLower = this._sqlLower || ''
          const bindings = this._bindings || []

          // INSERT with RETURNING (used in registration)
          if (sqlLower.includes('insert into users') && sqlLower.includes('returning')) {
            const user = {
              id: idCounter++,
              email: bindings[0],
              password_hash: bindings[1],
              role: bindings[2] || 'viewer',
              enabled: 1,
              created_at: new Date().toISOString(),
            }
            users.push(user)
            return { id: user.id, email: user.email, role: user.role, created_at: user.created_at }
          }

          // INSERT node with RETURNING
          if (sqlLower.includes('insert into nodes') && sqlLower.includes('returning')) {
            const node = {
              id: idCounter++,
              name: bindings[0],
              host: bindings[1],
              port: bindings[2] || 22,
              status: 'offline',
              config: bindings[3],
              created_at: new Date().toISOString(),
            }
            nodes.push(node)
            return node
          }

          // User queries - check for enabled = 1 condition
          if (sqlLower.includes('from users') && sqlLower.includes('where email')) {
            const user = users.find(u => u.email === bindings[0])
            if (user && sqlLower.includes('enabled = 1') && user.enabled !== 1) {
              return null
            }
            return user || null
          }
          if (sqlLower.includes('from users where id')) {
            // Handle both string and number id comparison
            const id = typeof bindings[0] === 'string' ? parseInt(bindings[0], 10) : bindings[0]
            return users.find(u => u.id === id) || null
          }

          // Password hash update
          if (sqlLower.includes('select password_hash from users where id')) {
            const user = users.find(u => u.id === bindings[0])
            return user ? { password_hash: user.password_hash } : null
          }

          // Check if user exists (for registration duplicate check)
          if (sqlLower.includes('select id from users where email')) {
            return users.find(u => u.email === bindings[0]) || null
          }

          // MFA queries
          if (sqlLower.includes('from user_mfa where user_id')) {
            return userMfa.find(m => m.user_id === bindings[0]) || null
          }

          // Node queries
          if (sqlLower.includes('from nodes where id')) {
            return nodes.find(n => n.id === bindings[0]) || null
          }
          if (sqlLower.includes('select id from nodes where name')) {
            return nodes.find(n => n.name === bindings[0]) || null
          }

          // Playbook queries
          if (sqlLower.includes('from playbooks where name')) {
            return playbooks.find(p => p.name === bindings[0]) || null
          }
          if (sqlLower.includes('from playbooks where id')) {
            return playbooks.find(p => p.id === bindings[0]) || null
          }

          // Count queries
          if (sqlLower.includes('count(')) {
            return { count: 1, total: 1 }
          }

          // Tenant queries
          if (sqlLower.includes('insert into tenants') && sqlLower.includes('returning')) {
            const tenant = {
              id: idCounter++,
              name: bindings[0],
              slug: bindings[1],
              plan: bindings[2] || 'free',
              status: 'active',
              quotas: bindings[3],
              billing_email: bindings[4] || null,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            }
            tenants.push(tenant)
            return tenant
          }
          if (sqlLower.includes('from tenants where id')) {
            return tenants.find(t => t.id === bindings[0]) || null
          }
          if (sqlLower.includes('from tenants where slug')) {
            return tenants.find(t => t.slug === bindings[0]) || null
          }

          // Role queries
          if (sqlLower.includes('from roles where id')) {
            return roles.find(r => r.id === bindings[0]) || null
          }
          if (sqlLower.includes('from roles where name')) {
            return roles.find(r => r.name === bindings[0]) || null
          }
          if (sqlLower.includes('insert into roles') && sqlLower.includes('returning')) {
            const role = {
              id: idCounter++,
              tenant_id: bindings[0],
              name: bindings[1],
              display_name: bindings[2] || null,
              description: bindings[3] || null,
              permissions: bindings[4],
              is_system: false,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            }
            roles.push(role)
            return role
          }

          // Tenant member queries
          if (sqlLower.includes('from tenant_members where user_id')) {
            return tenantMembers.find(m => m.user_id === bindings[0] && m.tenant_id === bindings[1]) || null
          }
          if (sqlLower.includes('insert into tenant_members') && sqlLower.includes('returning')) {
            const member = {
              id: idCounter++,
              tenant_id: bindings[0],
              user_id: bindings[1],
              role_id: bindings[2] || null,
              invited_by: bindings[3] || null,
              joined_at: new Date().toISOString(),
            }
            tenantMembers.push(member)
            return member
          }

          // Invitation queries
          if (sqlLower.includes('from tenant_invitations where token')) {
            return tenantInvitations.find(i => i.token === bindings[0]) || null
          }
          if (sqlLower.includes('insert into tenant_invitations') && sqlLower.includes('returning')) {
            const invitation = {
              id: idCounter++,
              tenant_id: bindings[0],
              email: bindings[1],
              role_id: bindings[2] || null,
              invited_by: bindings[3],
              token: bindings[4],
              expires_at: bindings[5],
              created_at: new Date().toISOString(),
            }
            tenantInvitations.push(invitation)
            return invitation
          }

          // Permission queries
          if (sqlLower.includes('from permissions')) {
            return { results: permissions }
          }

          return null
        }),
        all: vi.fn(async function(this: any) {
          const sqlLower = this._sqlLower || ''

          if (sqlLower.includes('from users')) {
            return { results: users }
          }
          if (sqlLower.includes('from nodes')) {
            return { results: nodes }
          }
          if (sqlLower.includes('from playbooks')) {
            return { results: playbooks }
          }
          if (sqlLower.includes('from tasks')) {
            return { results: tasks }
          }
          if (sqlLower.includes('from notifications')) {
            return { results: notifications }
          }
          if (sqlLower.includes('from audit_logs')) {
            return { results: auditLogs }
          }
          if (sqlLower.includes('from tenants')) {
            return { results: tenants }
          }
          if (sqlLower.includes('from tenant_members')) {
            return { results: tenantMembers }
          }
          if (sqlLower.includes('from roles')) {
            return { results: roles }
          }
          if (sqlLower.includes('from permissions')) {
            return { results: permissions }
          }
          if (sqlLower.includes('from tenant_invitations')) {
            return { results: tenantInvitations }
          }
          if (sqlLower.includes('from task_logs')) {
            return { results: taskLogs }
          }

          return { results: [] }
        }),
        run: vi.fn(async function(this: any) {
          const sqlLower = this._sqlLower || ''
          const bindings = this._bindings || []

          // INSERT user
          if (sqlLower.includes('insert into users')) {
            const user = {
              id: idCounter++,
              email: bindings[0],
              password_hash: bindings[1],
              role: bindings[2] || 'viewer',
              enabled: 1,
              created_at: new Date().toISOString(),
            }
            users.push(user)
            return { success: true, results: [user], meta: { last_row_id: user.id } }
          }

          // INSERT node
          if (sqlLower.includes('insert into nodes')) {
            const node = {
              id: idCounter++,
              name: bindings[0],
              host: bindings[1],
              port: bindings[2] || 22,
              status: 'offline',
              created_at: new Date().toISOString(),
            }
            nodes.push(node)
            return { success: true, results: [node], meta: { last_row_id: node.id } }
          }

          // INSERT playbook
          if (sqlLower.includes('insert into playbooks')) {
            const playbook = {
              id: idCounter++,
              name: bindings[0],
              storage_key: bindings[1],
              description: bindings[2],
              category: bindings[3] || 'custom',
              created_at: new Date().toISOString(),
            }
            playbooks.push(playbook)
            return { success: true, results: [playbook] }
          }

          // INSERT MFA
          if (sqlLower.includes('insert into user_mfa')) {
            const mfa = {
              id: idCounter++,
              user_id: bindings[0],
              secret: bindings[1],
              recovery_codes: bindings[2],
              verified: 0,
            }
            userMfa.push(mfa)
            return { success: true }
          }

          // UPDATE user last login
          if (sqlLower.includes('update users set last_login')) {
            const user = users.find(u => u.id === bindings[1])
            if (user) user.last_login_at = new Date().toISOString()
            return { success: true }
          }

          // INSERT tenant
          if (sqlLower.includes('insert into tenants')) {
            const tenant = {
              id: idCounter++,
              name: bindings[0],
              slug: bindings[1],
              plan: bindings[2] || 'free',
              status: 'active',
              quotas: bindings[3],
              created_at: new Date().toISOString(),
            }
            tenants.push(tenant)
            return { success: true, results: [tenant] }
          }

          // UPDATE tenant
          if (sqlLower.includes('update tenants')) {
            return { success: true, meta: { changes: 1 } }
          }

          // INSERT tenant member
          if (sqlLower.includes('insert into tenant_members')) {
            const member = {
              id: idCounter++,
              tenant_id: bindings[0],
              user_id: bindings[1],
              role_id: bindings[2] || null,
              invited_by: bindings[3] || null,
              joined_at: new Date().toISOString(),
            }
            tenantMembers.push(member)
            return { success: true }
          }

          // DELETE tenant member
          if (sqlLower.includes('delete from tenant_members')) {
            const idx = tenantMembers.findIndex(m => m.tenant_id === bindings[0] && m.user_id === bindings[1])
            if (idx >= 0) tenantMembers.splice(idx, 1)
            return { success: true }
          }

          // INSERT role
          if (sqlLower.includes('insert into roles')) {
            const role = {
              id: idCounter++,
              tenant_id: bindings[0],
              name: bindings[1],
              display_name: bindings[2] || null,
              description: bindings[3] || null,
              permissions: bindings[4],
              is_system: false,
              created_at: new Date().toISOString(),
            }
            roles.push(role)
            return { success: true }
          }

          // UPDATE role
          if (sqlLower.includes('update roles')) {
            return { success: true, meta: { changes: 1 } }
          }

          // DELETE role
          if (sqlLower.includes('delete from roles')) {
            const idx = roles.findIndex(r => r.id === bindings[0] && r.tenant_id === bindings[1])
            if (idx >= 0) roles.splice(idx, 1)
            return { success: true }
          }

          // INSERT tenant invitation
          if (sqlLower.includes('insert into tenant_invitations')) {
            const invitation = {
              id: idCounter++,
              tenant_id: bindings[0],
              email: bindings[1],
              role_id: bindings[2] || null,
              invited_by: bindings[3],
              token: bindings[4],
              expires_at: bindings[5],
              created_at: new Date().toISOString(),
            }
            tenantInvitations.push(invitation)
            return { success: true }
          }

          // UPDATE tenant invitation
          if (sqlLower.includes('update tenant_invitations')) {
            return { success: true }
          }

          // DELETE tenant invitation
          if (sqlLower.includes('delete from tenant_invitations')) {
            const idx = tenantInvitations.findIndex(i => i.id === bindings[0])
            if (idx >= 0) tenantInvitations.splice(idx, 1)
            return { success: true }
          }

          // INSERT task log
          if (sqlLower.includes('insert into task_logs')) {
            const log = {
              id: idCounter++,
              task_id: bindings[0],
              node_id: bindings[1] || null,
              node_name: bindings[2] || null,
              level: bindings[3],
              message: bindings[4],
              metadata: bindings[5] || null,
              created_at: new Date().toISOString(),
            }
            taskLogs.push(log)
            return { success: true }
          }

          // INSERT audit log
          if (sqlLower.includes('insert into audit_logs')) {
            const log = {
              id: idCounter++,
              tenant_id: bindings[0] || null,
              user_id: bindings[1] || null,
              action: bindings[2],
              resource: bindings[3],
              ip: bindings[4] || null,
              user_agent: bindings[5] || null,
              details: bindings[6] || null,
              created_at: new Date().toISOString(),
            }
            auditLogs.push(log)
            return { id: log.id }
          }

          return { success: true, meta: { changes: 1 } }
        }),
      }
    }) as any,

    batch: vi.fn(async (statements: any[]) => {
      return statements.map(() => ({ success: true }))
    }) as any,

    exec: vi.fn(async (sql: string) => {
      return { count: 0 }
    }) as any,

    withSession: vi.fn(() => createMockD1()) as any,

    dump: vi.fn(async () => {
      return new ArrayBuffer(0)
    }) as any,
  }
}

// Global test environment
declare global {
  var testEnv: {
    KV: KVNamespace
    R2: R2Bucket
    DB: D1Database
    JWT_SECRET: string
    JWT_EXPIRE: string
    API_KEY_SALT: string
    ENVIRONMENT: string
  }
}

beforeAll(() => {
  globalThis.testEnv = {
    KV: createMockKV(),
    R2: createMockR2(),
    DB: createMockD1(),
    JWT_SECRET: 'test-secret-key-for-testing-min-32-characters',
    JWT_EXPIRE: '86400',
    API_KEY_SALT: 'test-salt',
    ENVIRONMENT: 'test',
  }
})