export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const origin = request.headers.get('Origin')
    if (request.method === 'OPTIONS') {
      const headers = new Headers()
      if (origin) {
        headers.set('Access-Control-Allow-Origin', origin)
        headers.set('Access-Control-Allow-Credentials', 'true')
      } else {
        headers.set('Access-Control-Allow-Origin', '*')
      }
      headers.set('Access-Control-Allow-Methods', 'GET,HEAD,POST,OPTIONS')
      const reqHeaders = request.headers.get('Access-Control-Request-Headers')
      if (reqHeaders) headers.set('Access-Control-Allow-Headers', reqHeaders)
      headers.set('Access-Control-Max-Age', '86400')
      headers.set('Vary', 'Origin')
      return new Response(null, { status: 204, headers })
    }

    const url: URL = new URL(request.url)
    const pathname: string = url.pathname
    let hostname: string | undefined = pathname.split('/').filter(Boolean)[0]
    let referer: string | null = request.headers.get('Referer')

    if (!hostname?.startsWith('~')) {
      hostname = '~i.pximg.net'
      referer = 'https://pixiv.net'
    }

    url.pathname = pathname.replace(`/${hostname}`, '')
    url.hostname = hostname.slice(1)

    const res = await fetch(new Request(url, request), {
      headers: {
        ...(referer && { Referer: referer })
      }
    })
    const headers = new Headers(res.headers)
    if (origin) {
      headers.set('Access-Control-Allow-Origin', origin)
      headers.set('Access-Control-Allow-Credentials', 'true')
    } else {
      headers.set('Access-Control-Allow-Origin', '*')
    }
    headers.set('Access-Control-Expose-Headers', 'Content-Length,Content-Type,Cache-Control,ETag,Accept-Ranges')
    headers.set('Vary', 'Origin')
    return new Response(res.body, { status: res.status, headers })
  }
} satisfies ExportedHandler<Env>
