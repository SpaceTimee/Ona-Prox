import { Hono, type Context } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { secureHeaders } from 'hono/secure-headers'

type ParsedTarget = { protocol: string; host: string; pathname: string; search: string }

/** Parse "host/path" into { host, pathname } */
const extractHostPath = (input: string): { host: string; pathname: string } => {
  const slashIdx = input.indexOf('/')
  return {
    host: slashIdx === -1 ? input : input.slice(0, slashIdx),
    pathname: slashIdx === -1 ? '/' : input.slice(slashIdx) || '/'
  }
}

/** Check whitelist/blacklist (case-insensitive, supports * + ? wildcards, escape with \) */
const isAllowed = (value: string, allowedList: string, blockedList: string): boolean => {
  const ESC = ['\uE000', '\uE001', '\uE002', '\uE003']
  const matches = (v: string, pattern: string): boolean => {
    const p = pattern
      .split('\\\\')
      .join(ESC[0])
      .split('\\*')
      .join(ESC[1])
      .split('\\+')
      .join(ESC[2])
      .split('\\?')
      .join(ESC[3])
    if (!/[*+?]/.test(p)) {
      return (
        v.toLowerCase() ===
        p
          .split(ESC[0])
          .join('\\')
          .split(ESC[1])
          .join('*')
          .split(ESC[2])
          .join('+')
          .split(ESC[3])
          .join('?')
          .toLowerCase()
      )
    }
    const regex = p
      .replace(/[.^${}()|[\]\\]/g, '\\$&')
      .split('*')
      .join('.*')
      .split('+')
      .join('.+')
      .split('?')
      .join('.')
      .split(ESC[0])
      .join('\\\\')
      .split(ESC[1])
      .join('\\*')
      .split(ESC[2])
      .join('\\+')
      .split(ESC[3])
      .join('\\?')
    return new RegExp(`^${regex}$`, 'i').test(v)
  }
  const allowed = allowedList ? allowedList.split(',').map((p) => p.trim()) : null
  const blocked = blockedList ? blockedList.split(',').map((p) => p.trim()) : null
  return (
    (!allowed || allowed.some((p) => matches(value, p))) &&
    !(blocked && blocked.some((p) => matches(value, p)))
  )
}

const isHostAllowed = (host: string, env: Env) =>
  isAllowed(host, env.ALLOWED_HOSTS as string, env.BLOCKED_HOSTS as string)

const isMethodAllowed = (method: string, env: Env) =>
  isAllowed(method, env.ALLOWED_METHODS as string, env.BLOCKED_METHODS as string)

/** Apply header rules: "Key: value", "-Key", "Key" */
const applyCustomHeaders = (headers: Headers, config: string) => {
  if (!config) return
  const ESC = ['\uE000', '\uE001']
  const items = config
    .split('\\\\')
    .join(ESC[0])
    .split('\\,')
    .join(ESC[1])
    .split(',')
    .map((s) => s.split(ESC[0]).join('\\\\').split(ESC[1]).join(',').trim())
  for (const item of items) {
    if (!item) continue
    if (item.startsWith('-')) {
      headers.delete(item.slice(1).trim())
    } else {
      const colonIdx = item.indexOf(':')
      const key = colonIdx === -1 ? item : item.slice(0, colonIdx).trim()
      const value = (colonIdx === -1 ? '' : item.slice(colonIdx + 1).trim()).split('\\\\').join('\\')
      headers.set(key, value)
    }
  }
}

const proxy = async (
  c: Context,
  env: Env,
  protocol: string,
  host: string,
  pathname: string,
  search?: string
) => {
  if (
    !isAllowed(
      c.req.header('CF-Connecting-IP') || '',
      env.ALLOWED_IPS as string,
      env.BLOCKED_IPS as string
    ) ||
    !isHostAllowed(host, env)
  )
    return c.text('Forbidden', 403)
  if (!isMethodAllowed(c.req.method, env)) return c.text('Method Not Allowed', 405)

  const reqHeaders = new Headers(c.req.raw.headers)
  reqHeaders.delete('Host')
  if (!env.DISABLE_REFERER_SPOOF) reqHeaders.set('Referer', `${protocol}://${host}/`)
  applyCustomHeaders(reqHeaders, env.REQUEST_HEADERS as string)

  const url = Object.assign(new URL(c.req.url), { protocol, host, pathname })
  if (search !== undefined) url.search = search

  const res = await fetch(url, {
    method: c.req.method,
    headers: reqHeaders,
    body: c.req.raw.body,
    redirect: env.DISABLE_REDIRECT ? 'manual' : 'follow'
  })

  const resHeaders = new Headers(res.headers)
  applyCustomHeaders(resHeaders, env.RESPONSE_HEADERS as string)

  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: resHeaders })
}

const parseTarget = (target: string, env: Env, skipFallback = false): ParsedTarget | null => {
  const defaultProtocol = env.DEFAULT_HTTP ? 'http' : 'https'
  const normalized = target
    .trim()
    .replace(/^(https?):\/+/i, '$1://')
    .replace(/^\/{3,}/, '//')
    .replace(/^(https?|[~-])\/+/i, '$1/')
    .replace(/(?<!^)\/{2,}/g, '/')

  if (!env.DISABLE_FULL_PROTOCOL && /^https?:\/\//i.test(normalized)) {
    try {
      const url = new URL(normalized)
      return {
        protocol: url.protocol.slice(0, -1),
        host: url.host,
        pathname: url.pathname,
        search: url.search
      }
    } catch {
      /* fall through */
    }
  }

  if (!env.DISABLE_IMPLICIT_PROTOCOL && /^\/\/[^/]/.test(normalized)) {
    const rest = normalized.slice(2)
    const { host, pathname } = extractHostPath(rest.split('?')[0])
    return {
      protocol: defaultProtocol,
      host,
      pathname,
      search: rest.indexOf('?') === -1 ? '' : rest.slice(rest.indexOf('?'))
    }
  }

  const searchIdx = normalized.indexOf('?')
  const search = searchIdx === -1 ? '' : normalized.slice(searchIdx)
  const pathPart = searchIdx === -1 ? normalized : normalized.slice(0, searchIdx)

  if (!env.DISABLE_SEGMENTED_PROTOCOL) {
    const match = pathPart.match(/^(https?)\/(.+)/i)
    if (match) {
      const { host, pathname } = extractHostPath(match[2])
      return { protocol: match[1].toLowerCase(), host, pathname, search }
    }
  }

  if (!env.DISABLE_SLASH_SHORTHAND) {
    const match = pathPart.match(/^([~-])\/(.+)/)
    if (match) {
      const { host, pathname } = extractHostPath(match[2])
      return { protocol: match[1] === '~' ? 'https' : 'http', host, pathname, search }
    }
  }

  if (!env.DISABLE_COMPACT_SHORTHAND) {
    const match = pathPart.match(/^([~-])(.+)/)
    if (match) {
      const { host, pathname } = extractHostPath(match[2])
      return { protocol: match[1] === '~' ? 'https' : 'http', host, pathname, search }
    }
  }

  const slashIdx = pathPart.indexOf('/')
  const firstSeg = slashIdx === -1 ? pathPart : pathPart.slice(0, slashIdx)
  const isHost =
    firstSeg.startsWith('[') ||
    firstSeg.includes('.') ||
    (firstSeg.indexOf(':') !== -1 && firstSeg.indexOf(':', firstSeg.indexOf(':') + 1) !== -1)
  if (!env.DISABLE_IMPLICIT_PROTOCOL && isHost) {
    return {
      protocol: defaultProtocol,
      host: firstSeg,
      pathname: slashIdx === -1 ? '/' : pathPart.slice(slashIdx) || '/',
      search
    }
  }

  if (!env.DISABLE_FALLBACK_PROXY && !skipFallback) {
    return {
      protocol: defaultProtocol,
      host: (env.FALLBACK_HOST as string) || 'i.pximg.net',
      pathname: pathPart.startsWith('/') ? pathPart : '/' + pathPart,
      search
    }
  }
  return null
}

export default new Hono<{ Bindings: Env }>()
  .use('*', async (c, next) => {
    if (!c.env.DISABLE_LOGGER) return logger()(c, next)
    await next()
  })
  .use('*', secureHeaders({ crossOriginResourcePolicy: 'cross-origin' }))
  .use('*', (c, next) =>
    cors({
      origin: (origin) =>
        !origin
          ? '*'
          : isAllowed(origin, c.env.ALLOWED_ORIGINS as string, c.env.BLOCKED_ORIGINS as string)
            ? origin
            : ''
    })(c, next)
  )
  .onError((_, c) => c.text('Internal Server Error', 500))
  .all('*', (c) => {
    const { path } = c.req
    const { env } = c

    if (!env.DISABLE_PATH_PROXY) {
      const match = path.match(/^\/([~-][^/]*|https?)\/(.*)$/i)
      if (match) {
        const parsed = parseTarget(`${match[1]}/${match[2]}`, env, true)
        if (parsed) return proxy(c, env, parsed.protocol, parsed.host, parsed.pathname)
      }
    }

    if (path.length > 1) {
      const parsed = parseTarget(path.slice(1), env)
      if (parsed) return proxy(c, env, parsed.protocol, parsed.host, parsed.pathname)
    }

    if (!env.DISABLE_PARAM_PROXY) {
      const url = new URL(c.req.url)
      const targetUrl = url.searchParams.get(env.PARAM_NAME)
      if (targetUrl) {
        let fullUrl = targetUrl
        if (!env.DISABLE_PARAM_MERGE) {
          url.searchParams.delete(env.PARAM_NAME)
          const rest = url.searchParams.toString()
          if (rest) fullUrl += (targetUrl.includes('?') ? '&' : '?') + rest
        }
        const parsed = parseTarget(fullUrl, env)
        if (parsed) return proxy(c, env, parsed.protocol, parsed.host, parsed.pathname, parsed.search)
      }
    }

    if (path === '/') {
      const target = (env.ROOT_PAGE as string) || (env.FALLBACK_HOST as string) || 'i.pximg.net'
      const parsed = parseTarget(target, env, true)
      if (parsed) return proxy(c, env, parsed.protocol, parsed.host, parsed.pathname, parsed.search)
    }

    if (env.ERROR_PAGE) {
      const parsed = parseTarget(env.ERROR_PAGE as string, env, true)
      if (parsed) return proxy(c, env, parsed.protocol, parsed.host, parsed.pathname, parsed.search)
    }
    return c.text('Not Found', 404)
  })
