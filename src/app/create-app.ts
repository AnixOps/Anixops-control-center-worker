import type { Hono } from 'hono'
import type { Env } from '../types'
import { registerAuthRoutes } from './register-auth'
import { registerPlatformRoutes } from './register-platform'

export function createApp(app: Hono<{ Bindings: Env }>) {
  // Compose shared platform and auth routes in one place.
  registerPlatformRoutes(app)
  registerAuthRoutes(app)
  return app
}
