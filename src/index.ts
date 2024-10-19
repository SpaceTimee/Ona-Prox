export default {
  async fetch(request): Promise<Response> {
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

    return fetch(new Request(url, request), {
      headers: {
        ...(referer && { Referer: referer })
      }
    })
  }
} satisfies ExportedHandler<Env>
