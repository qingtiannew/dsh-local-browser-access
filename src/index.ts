/** Local loopback browser access without the Web startup token. */
import type { Context } from '@deepseek-ai/cordis'
import type { ConnectionTrustRequest, HostConnectionHandle, PeerScope } from '@deepseek-ai/dsh-client-connection'
import { isLoopbackHost } from '@deepseek-ai/dsh-host-webserver'
import type {} from '@deepseek-ai/dsh-client-connection'
import type {} from '@deepseek-ai/dsh-host-webserver'

/** Stable Cordis plugin name. */
export const name = 'dsh-local-browser-access'

/** Wait for the Host Connection and its authentication registry. */
export const inject = ['connection', 'connection.authentication']

/** Authentication registry service exposed by the local DSH source API. */
interface LocalConnectionAuthentication {
  register(provider: {
    authenticate(request: ConnectionTrustRequest): PeerScope | undefined
  }): () => Promise<void>
}

/** Local declaration for WebServer authorization facts absent from the published type bundle. */
interface LocalWebAuthRequest {
  headers: ConnectionTrustRequest['headers']
  method?: string | undefined
  url: URL
  transport: 'http' | 'upgrade'
  signal?: AbortSignal | undefined
  socket?: { readonly destroyed: boolean } | undefined
}

/** Admission result shape used by the WebServer authorization event. */
type LocalWebAdmission =
  | { kind: 'allow'; peer?: PeerScope }
  | { kind: 'deny'; status: 401 | 403 | 503 }

declare module '@deepseek-ai/cordis' {
  interface Events {
    'webserver/authorize'(request: LocalWebAuthRequest, policy: 'anonymous' | 'required' | 'deny'): LocalWebAdmission | undefined
  }
}

/** Read one Host authority from either Web Fetch or node:http headers. */
function requestHost(request: Pick<LocalWebAuthRequest, 'headers'>): string | undefined {
  const headers = request.headers
  if (headers instanceof Headers) return headers.get('host') ?? undefined
  const host = headers.host
  return typeof host === 'string' ? host : undefined
}

/** Read one request header from either the Fetch or node:http representation. */
function requestHeader(request: Pick<LocalWebAuthRequest, 'headers'>, name: string): string | undefined {
  const headers = request.headers
  if (headers instanceof Headers) return headers.get(name) ?? undefined
  const value = headers[name]
  return typeof value === 'string' ? value : undefined
}

/** Restrict the source-check exception to a bare top-level GET of the app shell. */
function isLoopbackDocumentNavigation(request: LocalWebAuthRequest): boolean {
  return request.method === 'GET'
    && request.url.pathname === '/'
    && request.url.search === ''
    && requestHeader(request, 'sec-fetch-mode') === 'navigate'
    && requestHeader(request, 'sec-fetch-dest') === 'document'
}

/** Accept only a bare loopback authority such as localhost:3080 or [::1]:3080. */
function isLoopbackAuthority(authority: string): boolean {
  if (authority !== authority.trim() || /[\s\\/@?#]/.test(authority)) return false
  let url: URL
  try {
    url = new URL(`http://${authority}`)
  } catch {
    return false
  }
  if (url.username !== '' || url.password !== '' || url.pathname !== '/' || url.search !== '' || url.hash !== '') return false
  if (url.hostname === 'localhost') return true
  const hostname = url.hostname.startsWith('[') && url.hostname.endsWith(']')
    ? url.hostname.slice(1, -1)
    : url.hostname
  return isLoopbackHost(hostname)
}

/**
 * Register a loopback-only fallback Peer when this Host has a local WebServer.
 * @param ctx - plugin scope with the Host Connection services.
 */
export function apply(ctx: Context): void {
  ctx.inject(['connection', 'connection.authentication', 'webServer'], (hostCtx) => {
    const webServer = hostCtx.get('webServer') as { readonly host: string } | undefined
    const connection = hostCtx.get('connection') as HostConnectionHandle | undefined
    const authentication = hostCtx.get('connection.authentication') as LocalConnectionAuthentication | undefined
    if (webServer === undefined || connection === undefined || authentication === undefined) {
      hostCtx.logger.warn('dsh-local-browser-access: disabled because required Host services could not be resolved')
      return
    }
    const bindHost = webServer.host
    const loopbackBind = typeof bindHost === 'string' && isLoopbackHost(bindHost)
    if (!loopbackBind) {
      hostCtx.logger.warn(
        `dsh-local-browser-access: disabled because webServer binds non-loopback address ${JSON.stringify(bindHost)}`,
      )
      return
    }

    const peer = connection.createPeer({ principal: { kind: 'owner' } })
    const removeDocumentAdmission = hostCtx.on('webserver/authorize', (request) => {
      const host = requestHost(request)
      if (host !== undefined && isLoopbackAuthority(host) && isLoopbackDocumentNavigation(request)) {
        return { kind: 'allow', peer }
      }
    }, { prepend: true })
    const unregister = authentication.register({
      authenticate(request): PeerScope | undefined {
        const host = requestHost(request)
        return host !== undefined && isLoopbackAuthority(host) ? peer : undefined
      },
    })

    hostCtx.effect(() => async () => {
      removeDocumentAdmission()
      await unregister()
      await peer.dispose()
    }, 'dsh-local-browser-access: loopback authentication')
    hostCtx.logger.info(`dsh-local-browser-access: enabled for loopback listener ${bindHost}; loopback document navigation only`)
  })
}
