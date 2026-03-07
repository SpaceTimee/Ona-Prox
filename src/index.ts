import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { secureHeaders } from 'hono/secure-headers'
import type { StatusCode } from 'hono/utils/http-status'

type ProxyTarget = { protocol: string; host: string; pathname: string; search: string }
type AccessRule = { exact?: string; regex?: RegExp }
type HeaderRule = { name: string; value?: string }

const parseAccessRules = (() => {
  const cache = new Map<string, AccessRule[]>()
  const escapes = ['\uE000', '\uE001', '\uE002', '\uE003']
  return (rules: string) => {
    const cached = cache.get(rules)
    if (cached) return cached
    const parsed = rules
      .trim()
      .split(/\s*,\s*/)
      .filter(Boolean)
      .map((pattern) => {
        const escaped = pattern
          .replaceAll('\\\\', escapes[0])
          .replaceAll('\\*', escapes[1])
          .replaceAll('\\+', escapes[2])
          .replaceAll('\\?', escapes[3])
        if (!/[*+?]/.test(escaped)) {
          return {
            exact: escaped
              .replaceAll(escapes[0], '\\')
              .replaceAll(escapes[1], '*')
              .replaceAll(escapes[2], '+')
              .replaceAll(escapes[3], '?')
              .toLowerCase()
          }
        }
        const regexSource = escaped
          .replace(/[.^${}()|[\]\\]/g, '\\$&')
          .replaceAll('*', '.*')
          .replaceAll('+', '.+')
          .replaceAll('?', '.')
          .replaceAll(escapes[0], '\\\\')
          .replaceAll(escapes[1], '\\*')
          .replaceAll(escapes[2], '\\+')
          .replaceAll(escapes[3], '\\?')
        return { regex: new RegExp(`^${regexSource}$`, 'i') }
      })
    cache.set(rules, parsed)
    return parsed
  }
})()

const checkAccess = (subject: string, allowed: string, blocked: string): boolean => {
  if (!allowed && !blocked) return true
  const matches = (rule: AccessRule) =>
    rule.exact ? subject.toLowerCase() === rule.exact : rule.regex?.test(subject)
  if (allowed && !parseAccessRules(allowed).some(matches)) return false
  return !blocked || !parseAccessRules(blocked).some(matches)
}

const applyHeaderRules = (() => {
  const cache = new Map<string, HeaderRule[]>()
  const escapes = ['\uE000', '\uE001']
  return (headers: Headers, rules: string) => {
    rules = rules?.trim()
    if (!rules) return
    const cached = cache.get(rules)
    if (cached) {
      for (const rule of cached) {
        if (rule.value === undefined) headers.delete(rule.name)
        else headers.set(rule.name, rule.value)
      }
      return
    }
    const parsed: HeaderRule[] = []
    for (let entry of rules
      .replaceAll('\\\\', escapes[0])
      .replaceAll('\\,', escapes[1])
      .split(/\s*,\s*/)
      .filter(Boolean)) {
      entry = entry.replaceAll(escapes[0], '\\\\').replaceAll(escapes[1], ',')
      if (entry.startsWith('-')) {
        parsed.push({ name: entry.slice(1).trim() })
        continue
      }
      const colonIndex = entry.indexOf(':')
      if (colonIndex === -1) continue
      const name = entry.slice(0, colonIndex).trim()
      const value = entry
        .slice(colonIndex + 1)
        .trim()
        .replaceAll('\\\\', '\\')
      parsed.push({ name, value })
    }
    cache.set(rules, parsed)
    for (const rule of parsed) {
      if (rule.value === undefined) headers.delete(rule.name)
      else headers.set(rule.name, rule.value)
    }
  }
})()

const parseUrlPath = (url: string) => {
  const queryIndex = url.indexOf('?')
  const path = queryIndex === -1 ? url : url.slice(0, queryIndex)
  const slashIndex = path.indexOf('/')
  return {
    host: (slashIndex === -1 ? path : path.slice(0, slashIndex)).toLowerCase(),
    pathname: slashIndex === -1 ? '/' : path.slice(slashIndex),
    search: queryIndex === -1 ? '' : url.slice(queryIndex)
  }
}

const parseProxyTarget = (
  target: string,
  env: Env,
  defaultProtocol: 'http' | 'https',
  fallbackHost: string,
  skipFallback = false
): ProxyTarget | null => {
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
    return { protocol: prefix, ...parseUrlPath(rest) }

  if (!env.DISABLE_SHORTHAND_PROTOCOL && (prefix === '~' || prefix === '-'))
    return { protocol: prefix === '~' ? 'https' : 'http', ...parseUrlPath(rest) }

  if (!env.DISABLE_IMPLICIT_PROTOCOL) {
    if (prefix === '') return { protocol: defaultProtocol, ...parseUrlPath(rest) }
    if (prefix.startsWith('[') || prefix.includes('.') || prefix.indexOf(':') !== prefix.lastIndexOf(':'))
      return { protocol: defaultProtocol, ...parseUrlPath(input) }
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
      origin: (origin, c) =>
        !origin
          ? '*'
          : checkAccess(origin, c.env.ALLOWED_ORIGINS_LIST, c.env.BLOCKED_ORIGINS_LIST)
            ? origin
            : ''
    })
  )
  .onError((_, c) => c.text('Internal Server Error', 500))
  .all('*', async (c) => {
    const { env } = c
    const requestUrl = new URL(c.req.url)
    const { hostname, pathname, searchParams } = requestUrl
    const deployDomain = env.PROXY_DEPLOY_DOMAIN?.toLowerCase() || ''
    const subdomainBase = env.SUBDOMAIN_PROXY_ROOT?.toLowerCase() || deployDomain
    const defaultProtocol = env.PREFER_HTTP_PROTOCOL ? 'http' : 'https'
    const fallbackHost = env.FALLBACK_PROXY_HOST || 'i.pximg.net'

    const proxy = async (target: string | ProxyTarget, skipFallback = false): Promise<Response | null> => {
      const parsed =
        typeof target === 'string'
          ? parseProxyTarget(target, env, defaultProtocol, fallbackHost, skipFallback)
          : target
      if (!parsed) return null

      if (deployDomain) {
        if (
          parsed.host === deployDomain ||
          parsed.host === subdomainBase ||
          parsed.host.endsWith('.' + subdomainBase)
        )
          return null
      }

      if (
        !checkAccess(c.req.header('CF-Connecting-IP') || '', env.ALLOWED_IPS_LIST, env.BLOCKED_IPS_LIST) ||
        !checkAccess(parsed.host, env.ALLOWED_HOSTS_LIST, env.BLOCKED_HOSTS_LIST)
      )
        return c.text('Forbidden', 403)
      if (!checkAccess(c.req.method, env.ALLOWED_METHODS_LIST, env.BLOCKED_METHODS_LIST))
        return c.text('Method Not Allowed', 405)

      const reqHeaders = new Headers(c.req.raw.headers)
      reqHeaders.delete('Host')
      if (!env.DISABLE_REFERER_SPOOF) reqHeaders.set('Referer', `${parsed.protocol}://${parsed.host}/`)
      applyHeaderRules(reqHeaders, env.REQUEST_HEADERS_RULES)

      const res = await fetch(`${parsed.protocol}://${parsed.host}${parsed.pathname}${parsed.search}`, {
        method: c.req.method,
        headers: reqHeaders,
        body: c.req.raw.body,
        redirect: env.DISABLE_REDIRECT_FOLLOW ? 'manual' : 'follow'
      })

      const resHeaders = new Headers(res.headers)
      applyHeaderRules(resHeaders, env.RESPONSE_HEADERS_RULES)

      return c.newResponse(res.body, { status: res.status as StatusCode, headers: resHeaders })
    }

    if (!env.DISABLE_SUBDOMAIN_PROXY && deployDomain && hostname !== deployDomain) {
      const suffix = '.' + subdomainBase
      if (hostname.endsWith(suffix)) {
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
      const paramName = env.PARAM_PROXY_NAME ?? ''
      const targetUrl = searchParams.get(paramName)
      if (targetUrl) {
        let target = targetUrl.replace(/^\/+/, '')
        if (!env.DISABLE_PARAM_MERGE) {
          searchParams.delete(paramName)
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
