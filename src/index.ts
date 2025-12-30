import { Hono, type Context } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { secureHeaders } from 'hono/secure-headers'

const proxy = async (context: Context, protocol: string, hostname: string, path: string) => {
  const headers = new Headers(context.req.raw.headers)

  headers.delete('Host')

  if (hostname === 'i.pximg.net') headers.set('Referer', 'https://pixiv.net')

  const response = await fetch(new URL(path, `${protocol}://${hostname}`), {
    method: context.req.method,
    headers,
    body: context.req.raw.body
  })

  return new Response(response.body, response)
}

export default new Hono<{ Bindings: Env }>()
  .use('*', logger(), secureHeaders(), cors())
  .onError((_, context) => context.text('Internal Server Error', 500))
  .all('/:prefix{(?:[~-][^/]*|https?)}/:rest{.*}', (context) => {
    const { prefix, rest } = context.req.param()
    const isSegmented = ['https', 'http', '~', '-'].includes(prefix)

    const protocol = prefix.startsWith('~') || prefix === 'https' ? 'https' : 'http'
    const hostname = isSegmented ? rest.split('/')[0] : prefix.slice(1)
    const path = isSegmented ? rest.substring(hostname.length) || '/' : '/' + rest

    return proxy(context, protocol, hostname, path)
  })
  .all('*', (context) => proxy(context, 'https', 'i.pximg.net', context.req.path))
