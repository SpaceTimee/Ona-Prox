import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { secureHeaders } from 'hono/secure-headers'

type Protocol = 'http' | 'https'
type ProxyTarget = { protocol: Protocol; host: string; pathname: string; search: string }
type AccessRule = { exact: string } | { regex: RegExp }

const parseAccessRules = (() => {
  const cache = new Map<string, AccessRule[]>()
  const escapes = ['\uE000', '\uE001', '\uE002', '\uE003']
  return (rules: string) => {
    const trimmedRules = rules.trim()
    const cachedRules = cache.get(trimmedRules)
    if (cachedRules !== undefined) return cachedRules

    const parsedRules = trimmedRules
      .split(/\s*,\s*/)
      .filter(Boolean)
      .map((pattern) => {
        const escapedPattern = pattern
          .replaceAll('\\\\', escapes[0])
          .replaceAll('\\*', escapes[1])
          .replaceAll('\\+', escapes[2])
          .replaceAll('\\?', escapes[3])
        if (!/[*+?]/.test(escapedPattern)) {
          return {
            exact: escapedPattern
              .replaceAll(escapes[0], '\\')
              .replaceAll(escapes[1], '*')
              .replaceAll(escapes[2], '+')
              .replaceAll(escapes[3], '?')
              .toLowerCase()
          }
        }
        const regexSource = escapedPattern
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
    cache.set(trimmedRules, parsedRules)
    return parsedRules
  }
})()

const checkAccess = (subject: string, allowed: string, blocked: string): boolean => {
  if (!allowed && !blocked) return true

  const normalizedSubject = subject.toLowerCase()
  const matchesRule = (rule: AccessRule) =>
    'exact' in rule ? normalizedSubject === rule.exact : rule.regex.test(subject)
  if (allowed && !parseAccessRules(allowed).some(matchesRule)) return false
  return !blocked || !parseAccessRules(blocked).some(matchesRule)
}

const applyHeaderRules = (() => {
  const cache = new Map<string, { name: string; value?: string }[]>()
  const escapes = ['\uE000', '\uE001']
  return (headers: Headers, rules: string) => {
    const trimmedRules = rules.trim()
    if (!trimmedRules) return

    let parsedRules = cache.get(trimmedRules)
    if (parsedRules === undefined) {
      parsedRules = []
      for (const rawEntry of trimmedRules
        .replaceAll('\\\\', escapes[0])
        .replaceAll('\\,', escapes[1])
        .split(/\s*,\s*/)
        .filter(Boolean)) {
        const entry = rawEntry.replaceAll(escapes[0], '\\\\').replaceAll(escapes[1], ',')
        if (entry.startsWith('-')) {
          parsedRules.push({ name: entry.slice(1).trim() })
          continue
        }
        const colonIndex = entry.indexOf(':')
        if (colonIndex === -1) continue
        parsedRules.push({
          name: entry.slice(0, colonIndex).trim(),
          value: entry
            .slice(colonIndex + 1)
            .trim()
            .replaceAll('\\\\', '\\')
        })
      }
      cache.set(trimmedRules, parsedRules)
    }
    for (const rule of parsedRules) {
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
  defaultProtocol: Protocol,
  fallbackHost: string,
  skipFallback = false
): ProxyTarget | null => {
  let input = target.trim().replace(/^(https?:|[~-])(?!\/)/i, '$1/')
  if (!input.includes('/')) input = `/${input}`

  const slashIndex = input.indexOf('/')
  const prefix = input.slice(0, slashIndex).toLowerCase()
  const rest = input.slice(slashIndex + 1).replace(/^\/+/, '')

  if (!env.DISABLE_FULL_PROTOCOL && (prefix === 'http:' || prefix === 'https:')) {
    try {
      const url = new URL(`${prefix}//${rest}`)
      return {
        protocol: prefix === 'http:' ? 'http' : 'https',
        host: url.host,
        pathname: url.pathname,
        search: url.search
      }
    } catch {
      /* invalid URL */
    }
  }

  if (!env.DISABLE_SEGMENTED_PROTOCOL && (prefix === 'http' || prefix === 'https'))
    return { protocol: prefix, ...parseUrlPath(rest) }

  if (!env.DISABLE_SHORTHAND_PROTOCOL && (prefix === '-' || prefix === '~'))
    return { protocol: prefix === '-' ? 'http' : 'https', ...parseUrlPath(rest) }

  if (!env.DISABLE_IMPLICIT_PROTOCOL) {
    if (prefix === '') return { protocol: defaultProtocol, ...parseUrlPath(rest) }
    if (prefix.startsWith('[') || prefix.includes('.') || prefix.indexOf(':') !== prefix.lastIndexOf(':'))
      return { protocol: defaultProtocol, ...parseUrlPath(input) }
  }

  if (!env.DISABLE_FALLBACK_PROXY && !skipFallback)
    return {
      protocol: defaultProtocol,
      host: fallbackHost,
      pathname: `/${input}`,
      search: ''
    }
  return null
}

export default new Hono<{ Bindings: Env }>()
  .use('*', (context, next) => (context.env.DISABLE_LOGGER_OUTPUT ? next() : logger()(context, next)))
  .use('*', secureHeaders({ crossOriginResourcePolicy: 'cross-origin' }))
  .use(
    '*',
    cors({
      origin: (origin, context) =>
        !origin
          ? '*'
          : checkAccess(origin, context.env.ALLOWED_ORIGINS_LIST, context.env.BLOCKED_ORIGINS_LIST)
            ? origin
            : ''
    })
  )
  .onError((_, context) => context.text('Internal Server Error', 500))
  .all('*', async (context) => {
    const { env } = context
    const { hostname, pathname, search, searchParams } = new URL(context.req.url)
    const deployDomain = env.PROXY_DEPLOY_DOMAIN.toLowerCase()
    const subdomainBase = env.SUBDOMAIN_PROXY_ROOT.toLowerCase() || deployDomain
    const defaultProtocol = env.PREFER_HTTP_PROTOCOL ? 'http' : 'https'
    const fallbackHost = env.FALLBACK_PROXY_HOST || 'i.pximg.net'

    const proxy = async (target: string | ProxyTarget, skipFallback = false): Promise<Response | null> => {
      const proxyTarget =
        typeof target === 'string'
          ? parseProxyTarget(target, env, defaultProtocol, fallbackHost, skipFallback)
          : target
      if (proxyTarget === null) return null

      if (
        deployDomain &&
        (proxyTarget.host === deployDomain ||
          proxyTarget.host === subdomainBase ||
          proxyTarget.host.endsWith(`.${subdomainBase}`))
      )
        return null

      if (
        !checkAccess(
          context.req.header('CF-Connecting-IP') ?? '',
          env.ALLOWED_IPS_LIST,
          env.BLOCKED_IPS_LIST
        ) ||
        !checkAccess(proxyTarget.host, env.ALLOWED_HOSTS_LIST, env.BLOCKED_HOSTS_LIST)
      )
        return context.text('Forbidden', 403)
      if (!checkAccess(context.req.method, env.ALLOWED_METHODS_LIST, env.BLOCKED_METHODS_LIST))
        return context.text('Method Not Allowed', 405)

      const requestHeaders = new Headers(context.req.raw.headers)
      requestHeaders.delete('Host')
      if (!env.DISABLE_REFERER_SPOOF)
        requestHeaders.set('Referer', `${proxyTarget.protocol}://${proxyTarget.host}/`)
      applyHeaderRules(requestHeaders, env.REQUEST_HEADERS_RULES)

      const upstreamResponse = await fetch(
        `${proxyTarget.protocol}://${proxyTarget.host}${proxyTarget.pathname}${proxyTarget.search}`,
        {
          method: context.req.method,
          headers: requestHeaders,
          body: context.req.raw.body,
          redirect: env.DISABLE_REDIRECT_FOLLOW ? 'manual' : 'follow'
        }
      )

      const responseHeaders = new Headers(upstreamResponse.headers)
      applyHeaderRules(responseHeaders, env.RESPONSE_HEADERS_RULES)

      return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers: responseHeaders
      })
    }

    const subdomainSuffix = `.${subdomainBase}`
    if (
      !env.DISABLE_SUBDOMAIN_PROXY &&
      deployDomain &&
      hostname !== deployDomain &&
      hostname.endsWith(subdomainSuffix)
    ) {
      const subdomain = hostname.slice(0, -subdomainSuffix.length)
      const separator = env.SUBDOMAIN_PROXY_SEPARATOR || '.'
      const response = await proxy({
        protocol: defaultProtocol,
        host: separator === '.' ? subdomain : subdomain.split(separator).join('.'),
        pathname,
        search
      })
      if (response) return response
    }

    if (!env.DISABLE_PATH_PROXY) {
      const pathMatch = pathname.match(/^\/([~-][^/]*|https?:?)\/*(.*)$/i)
      if (pathMatch) {
        const response = await proxy(`${pathMatch[1]}/${pathMatch[2]}`, true)
        if (response) return response
      }
    }

    if (pathname !== '/') {
      const response = await proxy(pathname.slice(1))
      if (response) return response
    }

    if (!env.DISABLE_PARAM_PROXY) {
      const targetUrl = searchParams.get(env.PARAM_PROXY_NAME)
      if (targetUrl) {
        let target = targetUrl.replace(/^\/+/, '')
        if (!env.DISABLE_PARAM_MERGE) {
          searchParams.delete(env.PARAM_PROXY_NAME)
          const remainingParams = searchParams.toString()
          if (remainingParams) target += `${targetUrl.includes('?') ? '&' : '?'}${remainingParams}`
        }
        const response = await proxy(target)
        if (response) return response
      }
    }

    if (pathname === '/') {
      const response = await proxy(env.ROOT_PAGE_URL || fallbackHost, true)
      if (response) return response
    }

    if (env.ERROR_PAGE_URL) {
      const response = await proxy(env.ERROR_PAGE_URL, true)
      if (response) return response
    }

    return context.text('Not Found', 404)
  })
