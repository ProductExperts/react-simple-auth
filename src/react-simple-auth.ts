const sessionKey = 'session'

export interface IProvider<T> {
  getOrigin(): string | undefined

  buildAuthorizeUrl(): string

  extractError(redirectUrl: string): Error | undefined

  extractSession(redirectUrl: string): T

  validateSession(session: T): boolean

  getAccessToken(session: T, resourceId: string): string

  getSignOutUrl(redirectUrl: string): string
}

export interface IAuthenticationService {
  acquireTokenAsync<T>(productName: string, provider: IProvider<T>, storage?: Storage, localWindow?: Window): Promise<T>

  restoreSession<T>(provider: IProvider<T>, storage?: Storage): T | undefined

  invalidateSession(storage?: Storage): void

  getAccessToken<T>(provider: IProvider<T>, resourceId: string, storage?: Storage): string
}

export const service: IAuthenticationService = {
  acquireTokenAsync: function<T>(
      productName: string,
    provider: IProvider<T>,
    storage: Storage = window.localStorage,
    localWindow: Window = window
  ): Promise<T> {
    // Create unique request key
    const requestKey = `react-simple-auth-request-key-${guid()}`

    // Create new window set to authorize url, with unique request key, and centered options
    const [width, height] = [500, 500]
    const windowOptions = {
      width,
      height,
      left: Math.floor(screen.width / 2 - width / 2) + ((screen as any).availLeft || 0),
      top: Math.floor(screen.height / 2 - height / 2)
    }

    const oauthAuthorizeUrl = provider.buildAuthorizeUrl()
    const windowOptionString = Object.entries(windowOptions)
      .map(([key, value]) => `${key}=${value}`)
      .join(',')
    const loginWindow = localWindow.open(oauthAuthorizeUrl, requestKey, windowOptionString)
    if (loginWindow) {

      const callback = (event: MessageEvent) => {
        const origin = provider.getOrigin()
        // console.log(event.origin);
        if (origin && event.origin !== origin) {
          return
        }
        if (!event.source){
          return;
        }

        let eventSource = event.source as Window;
        if (eventSource.self !== eventSource){
          /* this message is not from the window */
          return;
        }
        if (eventSource.name !== requestKey){
          return;
        }
        if (loginWindow.closed) {
          localWindow.removeEventListener('message', callback);
          return;
        }
        // console.log(event.data);
        storage.setItem(requestKey, event.data)
        let reply: String = 'done'
        // @ts-ignore
        loginWindow.postMessage(reply, event.origin)
        localWindow.removeEventListener('message', callback);

      };
      localWindow.addEventListener('message', callback);
    }
    return new Promise<any>((resolve, reject) => {
      // Poll for when the is closed
      const checkWindow = (loginWindow: Window | null) => {
        if (!loginWindow) {
          reject(false);
          return;
        }

        // If window is still open check again later
        if (!loginWindow.closed) {
          // console.log("timer expired");
          setTimeout(() => checkWindow(loginWindow), 100)
          return
        }

        const redirectUrl = storage.getItem(requestKey)
        storage.removeItem(requestKey)

        // Window was closed, but never reached the redirect.html due to user closing window or network error during authentication
        if (typeof redirectUrl !== 'string' || redirectUrl.length === 0) {
          reject(
            new Error(
              `${productName}: Login window was closed by the user or authentication was incomplete and never reached final redirect page.`
            )
          )
          return
        }

        // Window was closed, and reached the redirect.html; however there still might have been error during authentication, check url
        const error = provider.extractError(redirectUrl)
        if (error) {
          reject(error)
          return
        }

        // Window was closed, reached redirect.html and correctly added tokens to the url
        const session = provider.extractSession(redirectUrl)
        storage.setItem(sessionKey, JSON.stringify(session))
        resolve(session)
      }

      checkWindow(loginWindow)
    })
  },

  restoreSession<T>(provider: IProvider<T>, storage: Storage = window.localStorage): T | undefined {
    const sessionString = storage.getItem(sessionKey)
    if (typeof sessionString !== 'string' || sessionString.length === 0) {
      return undefined
    }

    const session: T = JSON.parse(sessionString)

    if (!provider.validateSession(session)) {
      storage.removeItem(sessionKey)
      return undefined
    }

    return session
  },

  invalidateSession(storage: Storage = window.localStorage): void {
    storage.removeItem(sessionKey)
  },

  getAccessToken<T>(
    provider: IProvider<T>,
    resourceId: string,
    storage: Storage = window.localStorage
  ): string {
    const sessionString = storage.getItem(sessionKey)
    if (typeof sessionString !== 'string' || sessionString.length === 0) {
      throw new Error(
        `You attempted to get access token for resource id: ${resourceId} from the session but the session did not exist`
      )
    }

    const session: T = JSON.parse(sessionString)

    return provider.getAccessToken(session, resourceId)
  }
}

export default service

function guid(): string {
  let d = new Date().getTime()
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c: string) {
    let r = (d + Math.random() * 16) % 16 | 0
    d = Math.floor(d / 16)
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16)
  })
}
