import { Hono, type Context } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { secureHeaders } from 'hono/secure-headers'

const proxy = async (context: Context, hostname: string, path: string) => {
  const headers = new Headers(context.req.raw.headers)
  headers.delete('Host')
  if (hostname === 'i.pximg.net') headers.set('Referer', 'https://pixiv.net')
  const response = await fetch(new URL(path, `https://${hostname}`), {
    method: context.req.method,
    headers,
    body: context.req.raw.body
  })
  return new Response(response.body, response)
}

export default new Hono<{ Bindings: Env }>()
  .use('*', logger(), secureHeaders(), cors())
  .onError((_, context) => context.text('Internal Server Error', 500))
  .all('/:target{~[^/]+}/:path{.*}', (context) =>
    proxy(context, context.req.param('target').slice(1), '/' + (context.req.param('path') || ''))
  )
  .all('*', (context) => proxy(context, 'i.pximg.net', context.req.path))
