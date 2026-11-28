# ArcanaGuardian.Admin.Web

The administration web application (React, TypeScript strict, Vite). It is built by `dotnet build` (see `ArcanaGuardian.Core.csproj`) and embedded in the exe, which serves it at `/admin`. Needs Node 22+.

| Command | What it does |
| --- | --- |
| `npm ci` | Install the locked dependencies (local to this folder) |
| `npm run api:generate` | Regenerate `src/api/schema.ts` from `docs/api/openapi.json` |
| `npm run api:check` | Fail if `schema.ts` is stale against the contract |
| `npm run typecheck` / `lint` / `test` | TypeScript, eslint (with jsx-a11y), vitest with axe-core |
| `npm run verify` | All of the above |
| `npm run build` | `api:check`, typecheck, then the production build into `dist` (embedded by MSBuild) |
| `npm run dev` | Vite dev server (base `/admin/`); the API is not proxied, use the built exe for real runs |

Rules: no browser storage except the two secrets of the API and the one waiting-authorization record (id, operation, title, summary; `src/api/client.ts`, this tab's `sessionStorage`, never `localStorage`), no inline script or style (strict CSP), same origin only, protected admin changes go through the authorization dialog (`src/features/authorization`). The service decides which confirmed actions the active admin session can apply and which require a fresh passkey assertion.
