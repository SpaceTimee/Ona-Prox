import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { secureHeaders } from 'hono/secure-headers'
import type { StatusCode } from 'hono/utils/http-status'

type ParsedTarget = { protocol: string; host: string; pathname: string; search: string }

const WILDCARD_ESCAPES = ['\uE000', '\uE001', '\uE002', '\uE003']
const HEADER_ESCAPES = ['\uE000', '\uE001']

const isAllowed = (value: string, allowedList: string, blockedList: string): boolean => {
  const toRules = (list: string) =>
    list
      .split(',')
      .map((rule) => rule.trim())
      .filter(Boolean)
  const matches = (pattern: string): boolean => {
    const escaped = pattern
      .split('\\\\')
      .join(WILDCARD_ESCAPES[0])
      .split('\\*')
      .join(WILDCARD_ESCAPES[1])
      .split('\\+')
      .join(WILDCARD_ESCAPES[2])
      .split('\\?')
      .join(WILDCARD_ESCAPES[3])
    if (!/[*+?]/.test(escaped)) {
      const normalized = escaped
        .split(WILDCARD_ESCAPES[0])
        .join('\\')
        .split(WILDCARD_ESCAPES[1])
        .join('*')
        .split(WILDCARD_ESCAPES[2])
        .join('+')
        .split(WILDCARD_ESCAPES[3])
        .join('?')
        .toLowerCase()
      return value.toLowerCase() === normalized
    }
    const regex = escaped
      .replace(/[.^${}()|[\]\\]/g, '\\$&')
      .split('*')
      .join('.*')
      .split('+')
      .join('.+')
      .split('?')
      .join('.')
      .split(WILDCARD_ESCAPES[0])
      .join('\\\\')
      .split(WILDCARD_ESCAPES[1])
      .join('\\*')
      .split(WILDCARD_ESCAPES[2])
      .join('\\+')
      .split(WILDCARD_ESCAPES[3])
      .join('\\?')
    return new RegExp(`^${regex}$`, 'i').test(value)
  }
  const allowed = allowedList ? toRules(allowedList) : []
  const blocked = blockedList ? toRules(blockedList) : []
  if (allowed.length === 0 && blocked.length === 0) return true
  return (allowed.length === 0 || allowed.some(matches)) && !blocked.some(matches)
}

const applyHeaders = (headers: Headers, rules: string) => {
  if (!rules || !rules.trim()) return
  for (const entry of rules
    .split('\\\\')
    .join(HEADER_ESCAPES[0])
    .split('\\,')
    .join(HEADER_ESCAPES[1])
    .split(',')
    .map((s) => s.split(HEADER_ESCAPES[0]).join('\\\\').split(HEADER_ESCAPES[1]).join(',').trim())
    .filter(Boolean)) {
    if (entry.startsWith('-')) {
      headers.delete(entry.slice(1).trim())
      continue
    }
    const colonIndex = entry.indexOf(':')
    headers.set(
      colonIndex === -1 ? entry : entry.slice(0, colonIndex).trim(),
      (colonIndex === -1 ? '' : entry.slice(colonIndex + 1).trim()).split('\\\\').join('\\')
    )
  }
}

const parseHostPath = (value: string) => {
  const queryIndex = value.indexOf('?')
  const path = queryIndex === -1 ? value : value.slice(0, queryIndex)
  const slashIndex = path.indexOf('/')
  return {
    host: slashIndex === -1 ? path : path.slice(0, slashIndex),
    pathname: slashIndex === -1 ? '/' : path.slice(slashIndex) || '/',
    search: queryIndex === -1 ? '' : value.slice(queryIndex)
  }
}

const parseTarget = (
  target: string,
  env: Env,
  defaultProtocol: 'http' | 'https',
  fallbackHost: string,
  skipFallback = false
): ParsedTarget | null => {
  let input = target.trim()
  input = input.replace(/^(https?:|[~-])(?!\/)/i, '$1/')
  if (!input.includes('/')) input = '/' + input

  const slashIndex = input.indexOf('/')
  const prefix = input.slice(0, slashIndex).toLowerCase()
  const rest = input.slice(slashIndex + 1).replace(/^\/+/, '')

  if (!env.DISABLE_FULL_PROTOCOL && (prefix === 'https:' || prefix === 'http:')) {
    try {
      const url = new URL(prefix + '//' + rest)
      return {
        protocol: url.protocol.slice(0, -1),
        host: url.host,
        pathname: url.pathname,
        search: url.search
      }
    } catch {
      /* invalid URL */
    }
  }

  if (!env.DISABLE_SEGMENTED_PROTOCOL && (prefix === 'https' || prefix === 'http'))
    return { protocol: prefix, ...parseHostPath(rest) }

  if (!env.DISABLE_SHORTHAND_PROTOCOL && (prefix === '~' || prefix === '-'))
    return { protocol: prefix === '~' ? 'https' : 'http', ...parseHostPath(rest) }

  if (!env.DISABLE_IMPLICIT_PROTOCOL) {
    if (prefix === '') return { protocol: defaultProtocol, ...parseHostPath(rest) }
    if (prefix.startsWith('[') || prefix.includes('.') || prefix.indexOf(':') !== prefix.lastIndexOf(':'))
      return { protocol: defaultProtocol, ...parseHostPath(input) }
  }

  if (!env.DISABLE_FALLBACK_PROXY && !skipFallback)
    return {
      protocol: defaultProtocol,
      host: fallbackHost,
      pathname: '/' + input,
      search: ''
    }
  return null
}

export default new Hono<{ Bindings: Env }>()
  .use('*', async (c, next) => {
    if (!c.env.DISABLE_LOGGER_OUTPUT) return logger()(c, next)
    await next()
  })
  .use('*', secureHeaders({ crossOriginResourcePolicy: 'cross-origin' }))
  .use(
    '*',
    cors({
      origin: (origin, c) => {
        if (!origin) return '*'
        return isAllowed(origin, c.env.ALLOWED_ORIGINS_LIST, c.env.BLOCKED_ORIGINS_LIST) ? origin : ''
      }
    })
  )
  .onError((_, c) => c.text('Internal Server Error', 500))
  .all('*', async (c) => {
    const { env } = c
    const requestUrl = new URL(c.req.url)
    const { hostname, pathname, searchParams } = requestUrl
    const deployDomain = env.PROXY_DEPLOY_DOMAIN.toLowerCase()
    const subdomainBase = (env.SUBDOMAIN_PROXY_ROOT || deployDomain).toLowerCase()
    const defaultProtocol = env.PREFER_HTTP_PROTOCOL ? 'http' : 'https'
    const fallbackHost = env.FALLBACK_PROXY_HOST || 'i.pximg.net'
    const proxy = async (target: string | ParsedTarget, skipFallback = false): Promise<Response | null> => {
      const parsed =
        typeof target === 'string'
          ? parseTarget(target, env, defaultProtocol, fallbackHost, skipFallback)
          : target
      if (!parsed) return null
      if (
        deployDomain &&
        (parsed.host.toLowerCase() === deployDomain ||
          parsed.host.toLowerCase() === subdomainBase ||
          parsed.host.toLowerCase().endsWith('.' + subdomainBase))
      )
        return null
      if (
        !isAllowed(c.req.header('CF-Connecting-IP') || '', env.ALLOWED_IPS_LIST, env.BLOCKED_IPS_LIST) ||
        !isAllowed(parsed.host, env.ALLOWED_HOSTS_LIST, env.BLOCKED_HOSTS_LIST)
      )
        return c.text('Forbidden', 403)
      if (!isAllowed(c.req.method, env.ALLOWED_METHODS_LIST, env.BLOCKED_METHODS_LIST))
        return c.text('Method Not Allowed', 405)

      const reqHeaders = new Headers(c.req.raw.headers)
      reqHeaders.delete('Host')
      if (!env.DISABLE_REFERER_SPOOF) reqHeaders.set('Referer', `${parsed.protocol}://${parsed.host}/`)
      applyHeaders(reqHeaders, env.REQUEST_HEADERS_RULES)

      const res = await fetch(
        Object.assign(new URL(requestUrl), {
          protocol: parsed.protocol,
          host: parsed.host,
          pathname: parsed.pathname,
          search: parsed.search
        }),
        {
          method: c.req.method,
          headers: reqHeaders,
          body: c.req.raw.body,
          redirect: env.DISABLE_REDIRECT_FOLLOW ? 'manual' : 'follow'
        }
      )

      const resHeaders = new Headers(res.headers)
      applyHeaders(resHeaders, env.RESPONSE_HEADERS_RULES)

      return c.newResponse(res.body, { status: res.status as StatusCode, headers: resHeaders })
    }

    if (!env.DISABLE_SUBDOMAIN_PROXY && deployDomain && hostname.toLowerCase() !== deployDomain) {
      const suffix = '.' + subdomainBase
      if (hostname.toLowerCase().endsWith(suffix)) {
        const subdomain = hostname.slice(0, -suffix.length)
        const separator = env.SUBDOMAIN_PROXY_SEPARATOR || '.'
        const result = await proxy({
          protocol: defaultProtocol,
          host: separator === '.' ? subdomain : subdomain.split(separator).join('.'),
          pathname,
          search: requestUrl.search
        })
        if (result) return result
      }
    }

    if (!env.DISABLE_PATH_PROXY) {
      const match = pathname.match(/^\/([~-][^/]*|https?:?)\/*(.*)$/i)
      if (match) {
        const result = await proxy(`${match[1]}/${match[2]}`, true)
        if (result) return result
      }
    }

    if (pathname !== '/') {
      const result = await proxy(pathname.slice(1))
      if (result) return result
    }

    if (!env.DISABLE_PARAM_PROXY) {
      const targetUrl = searchParams.get(env.PARAM_PROXY_NAME)
      if (targetUrl) {
        let target = targetUrl.replace(/^\/+/, '')
        if (!env.DISABLE_PARAM_MERGE) {
          searchParams.delete(env.PARAM_PROXY_NAME)
          const rest = searchParams.toString()
          if (rest) target += (targetUrl.includes('?') ? '&' : '?') + rest
        }
        const result = await proxy(target)
        if (result) return result
      }
    }

    if (pathname === '/') {
      const result = await proxy(env.ROOT_PAGE_URL || fallbackHost, true)
      if (result) return result
    }

    if (env.ERROR_PAGE_URL) {
      const result = await proxy(env.ERROR_PAGE_URL, true)
      if (result) return result
    }
    return c.text('Not Found', 404)
  })
