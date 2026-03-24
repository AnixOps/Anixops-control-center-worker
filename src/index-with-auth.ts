import { Hono } from 'hono'
import { hash, compare } from 'bcryptjs'
import { SignJWT, jwtVerify } from 'jose'

const app = new Hono()

app.get('/health', (c) => {
  return c.json({ status: 'healthy', timestamp: new Date().toISOString() })
})

app.get('/readiness', async (c) => {
  try {
    const result = await c.env.DB.prepare('SELECT 1').first()
    return c.json({ status: 'ready', db: !!result })
  } catch (err) {
    return c.json({ status: 'error', error: String(err) }, 500)
  }
})

app.post('/api/v1/auth/register', async (c) => {
  try {
    const body = await c.req.json()
    const { email, password, role } = body

    // Check if user exists
    const existing = await c.env.DB
      .prepare('SELECT id FROM users WHERE email = ?')
      .bind(email)
      .first()

    if (existing) {
      return c.json({ success: false, error: 'Email already registered' }, 409)
    }

    // Hash password
    const passwordHash = await hash(password, 12)

    // Create user
    const result = await c.env.DB
      .prepare('INSERT INTO users (email, password_hash, role, auth_provider, enabled) VALUES (?, ?, ?, ?, 1) RETURNING id, email, role')
      .bind(email, passwordHash, role || 'viewer', 'local')
      .first()

    return c.json({ success: true, data: result }, 201)
  } catch (err) {
    return c.json({ success: false, error: String(err) }, 500)
  }
})

app.post('/api/v1/auth/login', async (c) => {
  try {
    const body = await c.req.json()
    const { email, password } = body

    // Find user
    const user = await c.env.DB
      .prepare('SELECT * FROM users WHERE email = ? AND enabled = 1')
      .bind(email)
      .first<{ id: number; email: string; password_hash: string; role: string }>()

    if (!user || !user.password_hash) {
      return c.json({ success: false, error: 'Invalid credentials' }, 401)
    }

    // Verify password
    const valid = await compare(password, user.password_hash)
    if (!valid) {
      return c.json({ success: false, error: 'Invalid credentials' }, 401)
    }

    // Generate JWT
    const secret = new TextEncoder().encode(c.env.JWT_SECRET)
    const token = await new SignJWT({ sub: String(user.id), email: user.email, role: user.role })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('24h')
      .sign(secret)

    return c.json({ success: true, data: { token, user: { id: user.id, email: user.email, role: user.role } } })
  } catch (err) {
    return c.json({ success: false, error: String(err) }, 500)
  }
})

export default app