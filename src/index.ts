import { Hono, type Context } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { secureHeaders } from 'hono/secure-headers'

const proxy = async (context: Context, protocol: string, host: string, pathname: string) => {
  const headers = new Headers(context.req.raw.headers)

  headers.delete('Host')

  if (host === 'i.pximg.net') headers.set('Referer', 'https://pixiv.net')

  const response = await fetch(Object.assign(new URL(context.req.url), { protocol, host, pathname }), {
    method: context.req.method,
    headers,
    body: context.req.raw.body
  })

  return new Response(response.body, response)
}

export default new Hono<{ Bindings: Env }>()
  .use('*', logger(), secureHeaders({ crossOriginResourcePolicy: 'cross-origin' }), cors())
  .onError((_, context) => context.text('Internal Server Error', 500))
  .all('/:prefix{(?:[~-][^/]*|https?)}/:rest{.*}', (context) => {
    const { prefix, rest } = context.req.param()
    const isSegmented = ['https', 'http', '~', '-'].includes(prefix)

    const protocol = prefix.startsWith('~') || prefix === 'https' ? 'https' : 'http'
    const host = isSegmented ? rest.split('/')[0] : prefix.slice(1)
    const pathname = isSegmented ? rest.substring(host.length) || '/' : '/' + rest

    return proxy(context, protocol, host, pathname)
  })
  .all('*', (context) => proxy(context, 'https', 'i.pximg.net', context.req.path))
