/**
 * E2E Integration Tests
 *
 * These tests verify end-to-end flows across multiple handlers and services.
 * They use mocked infrastructure (D1, KV, R2) but test real business logic.
 *
 * Note: Each test suite creates its own mock environment, so tests within
 * a suite share state but different suites are isolated.
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest'
import app from '../src/index'
import type { Env } from '../src/types'
import { createMockKV, createMockR2, createMockD1 } from '../test/setup'

// Create test environment with shared mocks
function createTestEnv(): Env {
  return {
    ENVIRONMENT: 'development',
    JWT_SECRET: 'test-secret-key-for-e2e-tests-min-32-characters!',
    JWT_EXPIRE: '3600',
    API_KEY_SALT: 'test-salt-for-api-keys',
    DB: createMockD1(),
    KV: createMockKV(),
    R2: createMockR2(),
  }
}

describe('E2E: Health Check', () => {
  let env: Env

  beforeAll(() => {
    env = createTestEnv()
  })

  it('should return healthy status', async () => {
    const res = await app.request('/health', {}, env)
    expect(res.status).toBe(200)
    const data = await res.json() as { status: string }
    expect(data.status).toBe('healthy')
  })

  it('should return readiness status', async () => {
    const res = await app.request('/readiness', {}, env)
    expect(res.status).toBe(200)
    const data = await res.json() as { status: string; checks?: Record<string, boolean> }
    expect(data.status).toBe('ready')
  })
})

describe('E2E: Authentication Flow', () => {
  let env: Env
  let authToken: string
  let refreshToken: string

  beforeAll(() => {
    env = createTestEnv()
  })

  it('should register a new user', async () => {
    const res = await app.request('/api/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'TestPass123!',
        role: 'admin',
      }),
    }, env)

    expect(res.status).toBe(201)
    const data = await res.json() as { success: boolean; data?: { id: number; email: string } }
    expect(data.success).toBe(true)
    expect(data.data?.email).toBe('test@example.com')
  })

  it('should login with valid credentials', async () => {
    const res = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'TestPass123!',
      }),
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as { success: boolean; data?: { access_token: string; refresh_token: string } }
    expect(data.success).toBe(true)
    expect(data.data?.access_token).toBeDefined()
    authToken = data.data?.access_token || ''
    refreshToken = data.data?.refresh_token || ''
  })

  it('should access protected route with valid token', async () => {
    const res = await app.request('/api/v1/users/me', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as { success: boolean; data?: { email: string } }
    expect(data.success).toBe(true)
    expect(data.data?.email).toBe('test@example.com')
  })

  it('should reject request without token', async () => {
    const res = await app.request('/api/v1/users/me', {
      method: 'GET',
    }, env)
    expect(res.status).toBe(401)
  })

  it('should refresh tokens', async () => {
    const res = await app.request('/api/v1/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as { success: boolean; data?: { access_token: string } }
    expect(data.success).toBe(true)
    expect(data.data?.access_token).toBeDefined()
  })
})

describe('E2E: Node Management Flow', () => {
  let env: Env
  let authToken: string
  let nodeId: number

  beforeAll(async () => {
    env = createTestEnv()

    // Register and login
    await app.request('/api/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'nodeuser@example.com',
        password: 'NodeUser123!',
        role: 'admin',
      }),
    }, env)

    const loginRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'nodeuser@example.com',
        password: 'NodeUser123!',
      }),
    }, env)

    const loginData = await loginRes.json() as { data?: { access_token: string } }
    authToken = loginData.data?.access_token || ''
  })

  it('should create a node', async () => {
    const res = await app.request('/api/v1/nodes', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        name: 'test-server-1',
        host: '192.168.1.100',
        port: 22,
      }),
    }, env)

    expect(res.status).toBe(201)
    const data = await res.json() as { success: boolean; data?: { id: number; name: string } }
    expect(data.success).toBe(true)
    expect(data.data?.name).toBe('test-server-1')
    nodeId = data.data?.id || 0
  })

  it('should list nodes', async () => {
    const res = await app.request('/api/v1/nodes', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as { success: boolean; data?: { items: Array<{ id: number }> } }
    expect(data.success).toBe(true)
  })
})

describe('E2E: Playbook Flow', () => {
  let env: Env
  let authToken: string

  beforeAll(async () => {
    env = createTestEnv()

    // Register and login
    await app.request('/api/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'playbook@example.com',
        password: 'Playbook123!',
        role: 'admin',
      }),
    }, env)

    const loginRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'playbook@example.com',
        password: 'Playbook123!',
      }),
    }, env)

    const loginData = await loginRes.json() as { data?: { access_token: string } }
    authToken = loginData.data?.access_token || ''
  })

  it('should list built-in playbooks', async () => {
    const res = await app.request('/api/v1/playbooks/built-in', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as { success: boolean; data?: Array<{ name: string }> }
    expect(data.success).toBe(true)
    expect(data.data?.length).toBeGreaterThan(0)
  })

  it('should get playbook categories', async () => {
    const res = await app.request('/api/v1/playbooks/categories', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as { success: boolean; data?: Array<{ id: string }> }
    expect(data.success).toBe(true)
    expect(data.data?.length).toBeGreaterThan(0)
  })

  it('should get a specific built-in playbook', async () => {
    const res = await app.request('/api/v1/playbooks/install-fail2ban', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as { success: boolean; data?: { name: string; content: string } }
    expect(data.success).toBe(true)
    expect(data.data?.name).toBe('install-fail2ban')
    expect(data.data?.content).toContain('hosts: all')
  })
})

describe('E2E: MFA Flow', () => {
  let env: Env
  let authToken: string

  beforeAll(async () => {
    env = createTestEnv()

    // Register and login
    await app.request('/api/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'mfauser@example.com',
        password: 'MfaUser123!',
        role: 'admin',
      }),
    }, env)

    const loginRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'mfauser@example.com',
        password: 'MfaUser123!',
      }),
    }, env)

    const loginData = await loginRes.json() as { data?: { access_token: string } }
    authToken = loginData.data?.access_token || ''
  })

  it('should get MFA status (disabled initially)', async () => {
    const res = await app.request('/api/v1/mfa/status', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as { success: boolean; data?: { enabled: boolean } }
    expect(data.success).toBe(true)
    expect(data.data?.enabled).toBe(false)
  })

  it('should setup MFA', async () => {
    const res = await app.request('/api/v1/mfa/setup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({}),
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as {
      success: boolean
      data?: {
        secret: string
        otpauth_url: string
        recovery_codes: string[]
      }
    }
    expect(data.success).toBe(true)
    expect(data.data?.secret).toBeDefined()
    expect(data.data?.otpauth_url).toContain('otpauth://totp/')
    expect(data.data?.recovery_codes?.length).toBe(8)
  })
})

describe('E2E: AI and Vectorize Flow', () => {
  let env: Env
  let authToken: string

  beforeAll(async () => {
    env = createTestEnv()

    ;(env as Env & {
      AI: { run: (model: string, input: unknown) => Promise<unknown> }
      VECTORIZE: {
        upsert: (vectors: Array<{ id: string; values: number[]; metadata: Record<string, unknown> }>) => Promise<void>
        query: (embedding: number[], options: Record<string, unknown>) => Promise<{ matches: Array<{ id: string; score: number; metadata: Record<string, unknown> }> }>
        deleteByIds: (ids: string[]) => Promise<void>
        getByIds: (ids: string[]) => Promise<Array<{ id: string; values: number[]; metadata: Record<string, unknown> }>>
      }
    }).AI = {
      run: async (model: string) => {
        if (model.includes('bge-base-en-v1.5')) {
          return { embedding: [0.11, 0.22, 0.33] }
        }
        return { response: '{"result":"ok"}' }
      },
    }

    let insertedVectors: Array<{ id: string; values: number[]; metadata: Record<string, unknown> }> = []
    ;(env as Env & {
      VECTORIZE: {
        upsert: (vectors: Array<{ id: string; values: number[]; metadata: Record<string, unknown> }>) => Promise<void>
        query: (embedding: number[], options: Record<string, unknown>) => Promise<{ matches: Array<{ id: string; score: number; metadata: Record<string, unknown> }> }>
        deleteByIds: (ids: string[]) => Promise<void>
        getByIds: (ids: string[]) => Promise<Array<{ id: string; values: number[]; metadata: Record<string, unknown> }>>
      }
    }).VECTORIZE = {
      upsert: async (vectors) => {
        insertedVectors = [...insertedVectors, ...vectors]
      },
      query: async () => ({
        matches: insertedVectors.map((vector) => ({
          id: vector.id,
          score: 0.99,
          metadata: vector.metadata,
        })),
      }),
      deleteByIds: async (ids) => {
        insertedVectors = insertedVectors.filter((vector) => !ids.includes(vector.id))
      },
      getByIds: async (ids) => insertedVectors.filter((vector) => ids.includes(vector.id)),
    }

    await app.request('/api/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'aiuser@example.com',
        password: 'AiUser123!',
        role: 'admin',
      }),
    }, env)

    const loginRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'aiuser@example.com',
        password: 'AiUser123!',
      }),
    }, env)

    const loginData = await loginRes.json() as { data?: { access_token: string } }
    authToken = loginData.data?.access_token || ''
  })

  it('should generate embedding', async () => {
    const res = await app.request('/api/v1/ai/embedding', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({ text: 'deployment failed due to timeout' }),
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as { success: boolean; data?: { embedding?: number[] } }
    expect(data.success).toBe(true)
  })

  it('should insert and search vectors', async () => {
    const insertRes = await app.request('/api/v1/vectors', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        vectors: [
          {
            id: 'log-1',
            embedding: [0.11, 0.22, 0.33],
            metadata: {
              id: 'log-1',
              type: 'log',
              timestamp: '2026-03-23T00:00:00Z',
              level: 'error',
            },
          },
        ],
      }),
    }, env)

    expect(insertRes.status).toBe(200)

    const searchRes = await app.request('/api/v1/vectors/search', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        embedding: [0.11, 0.22, 0.33],
        topK: 5,
        type: 'log',
      }),
    }, env)

    expect(searchRes.status).toBe(200)
    const searchData = await searchRes.json() as { success: boolean; data?: Array<{ id: string }> }
    expect(searchData.success).toBe(true)
    expect(searchData.data?.[0]?.id).toBe('log-1')
  })

  it('should chat and translate natural language query', async () => {
    const chatRes = await app.request('/api/v1/ai/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        message: 'How do I troubleshoot a failed deployment?',
        history: [],
      }),
    }, env)

    expect(chatRes.status).toBe(200)

    const queryRes = await app.request('/api/v1/ai/query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        query: 'show failed tasks',
        schema: 'tasks(status, created_at)',
      }),
    }, env)

    expect(queryRes.status).toBe(200)
    const queryData = await queryRes.json() as { success: boolean; data?: { response?: string } }
    expect(queryData.success).toBe(true)
  })
})

describe('E2E: Web3 and IPFS Flow', () => {
  let env: Env
  let authToken: string
  const walletAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18'

  beforeAll(async () => {
    env = createTestEnv()

    await app.request('/api/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'web3user@example.com',
        password: 'Web3User123!',
        role: 'admin',
      }),
    }, env)

    const loginRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'web3user@example.com',
        password: 'Web3User123!',
      }),
    }, env)

    const loginData = await loginRes.json() as { data?: { access_token: string } }
    authToken = loginData.data?.access_token || ''
  })

  it('should issue a SIWE challenge', async () => {
    const res = await app.request('/api/v1/web3/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: walletAddress }),
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as { success: boolean; data?: { message: string; nonce: string } }
    expect(data.success).toBe(true)
    expect(data.data?.message).toContain(walletAddress)
    expect(data.data?.nonce).toBeDefined()
  })

  it('should verify a signed message', async () => {
    const challengeRes = await app.request('/api/v1/web3/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: walletAddress }),
    }, env)
    const challengeData = await challengeRes.json() as { data?: { message: string } }

    const verifyRes = await app.request('/api/v1/web3/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        address: walletAddress,
        signature: '0xmockedsignature',
        message: challengeData.data?.message,
      }),
    }, env)

    expect(verifyRes.status).toBe(200)
    const verifyData = await verifyRes.json() as { success: boolean; data?: { did: string } }
    expect(verifyData.success).toBe(true)
    expect(verifyData.data?.did).toContain('did:ethr:')
  })

  it('should upload to and retrieve from IPFS', async () => {
    const uploadRes = await app.request('/api/v1/ipfs/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        data: JSON.stringify({ hello: 'ipfs' }),
        filename: 'hello.json',
      }),
    }, env)

    expect(uploadRes.status).toBe(200)
    const uploadData = await uploadRes.json() as { success: boolean; data?: { cid: string } }
    expect(uploadData.success).toBe(true)
    expect(uploadData.data?.cid).toBeDefined()

    const getRes = await app.request(`/api/v1/ipfs/${uploadData.data?.cid}`, {
      method: 'GET',
    }, env)

    expect(getRes.status).toBe(200)
    const body = await getRes.text()
    expect(body).toContain('104')
    expect(body).toContain('112')
  })

  it('should store audit record on chain', async () => {
    const res = await app.request('/api/v1/web3/audit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        action: 'node.restart',
        userId: 1,
        timestamp: '2026-03-23T00:00:00Z',
        details: 'Restarted web3-enabled node',
      }),
    }, env)

    expect(res.status).toBe(200)
    const data = await res.json() as { success: boolean; data?: { txHash: string; ipfsCid: string } }
    expect(data.success).toBe(true)
    expect(data.data?.txHash).toContain('0x')
    expect(data.data?.ipfsCid).toBeDefined()
  })
})

describe('E2E: Realtime Endpoints Smoke', () => {
  let env: Env
  let authToken: string

  beforeAll(async () => {
    env = createTestEnv()

    await app.request('/api/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'realtime@example.com',
        password: 'Realtime123!',
        role: 'admin',
      }),
    }, env)

    const loginRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'realtime@example.com',
        password: 'Realtime123!',
      }),
    }, env)

    const loginData = await loginRes.json() as { data?: { access_token: string } }
    authToken = loginData.data?.access_token || ''
  })

  it('should reject SSE request without token', async () => {
    const res = await app.request('/api/v1/sse', { method: 'GET' }, env)
    expect(res.status).toBe(401)
  })

  it('should open SSE stream with valid token', async () => {
    const res = await app.request('/api/v1/sse', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toContain('text/event-stream')
    await res.body?.cancel()
  })

  it('should allow SSE subscribe/unsubscribe for valid channel', async () => {
    const subscribeRes = await app.request('/api/v1/sse/subscribe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({ channel: 'nodes' }),
    }, env)

    expect(subscribeRes.status).toBe(200)

    const unsubscribeRes = await app.request('/api/v1/sse/unsubscribe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({ channel: 'nodes' }),
    }, env)

    expect(unsubscribeRes.status).toBe(200)
  })

  it('should reject websocket upgrade when Upgrade header is missing', async () => {
    const res = await app.request('/api/v1/ws', {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    }, env)

    expect(res.status).toBe(426)
  })
})