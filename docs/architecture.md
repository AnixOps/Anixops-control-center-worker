# Architecture

This repository contains the independent Cloudflare Workers API backend for AnixOps Control Center.

- Runtime: Cloudflare Workers
- Framework: Hono
- Data: D1, KV, R2
- Auth: JWT

## IAM direction

- Worker-side auth is the control-plane boundary for both JWT and API key requests.
- Requests now resolve into a shared principal model so downstream handlers can treat identity consistently.
- This keeps the route layer stable while leaving room for future service identities and backend adapters.
- Cloudflare stays the edge/control-plane host, but the design should avoid making it the only place where identity or policy can exist.
