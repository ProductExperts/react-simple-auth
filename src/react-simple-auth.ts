import to from "./to";
import * as querystring from "querystring";

const sessionKey = 'session'

export interface Session {
    code: string | null,
    accessToken: string | null,
    refreshToken: string | null,
    expiresIn: number,
    createdAt: number
}

export interface IProvider<T extends Session> {
    getOrigin(): string | undefined

    buildAuthorizeUrl(): string

    buildTokenUrl(): string

    extractError(redirectUrl: string): Error | null

    extractSession(redirectUrl: string): T

    validateSession(session?: T): boolean

    getAccessTokenAsync(session?: T): Promise<string>

    signOut(session?: T): Promise<any>
}

export interface IToken<T extends Session> {
    renewed: boolean,
    session: T
}

export interface IAuthenticationService {
    load<T extends Session>(provider: IProvider<T>, payload: any, storage?: Storage): T

    acquireSessionAsync<T extends Session>(provider: IProvider<T>, storage?: Storage, localWindow?: Window): Promise<IToken<T>>

    accessToken<T extends Session>(provider: IProvider<T>, storage?: Storage): string | null

    invalidateSession<T extends Session>(provider: IProvider<T>, storage?: Storage): Promise<any>

    sessionIsValid<T extends Session>(provider: IProvider<T>, storage?: Storage): boolean

    hasSession(storage?: Storage): boolean
}

class ReactSimpleAuth implements IAuthenticationService {


    load<T extends Session>(provider: IProvider<T>, payload: any, storage: Storage = window.localStorage): T {
        const session = provider.extractSession(querystring.stringify(payload))
        if (session) {
            storage.setItem(sessionKey, JSON.stringify(session))
        }
        return session;
    }

    sessionIsValid<T extends Session>(provider: IProvider<T>, storage: Storage = window.localStorage): boolean {
        const session = this.restoreSession(provider, storage);
        return provider.validateSession(session);
    }

    accessToken<T extends Session>(provider: IProvider<T>, storage: Storage = window.localStorage): string | null {
        const session = this.restoreSession(provider, storage);
        if (session && provider.validateSession(session)) {
            return session.accessToken
        }
        return null;
    }

    acquireSessionAsync<T extends Session>(
        provider: IProvider<T>,
        storage: Storage = window.localStorage,
        localWindow: Window = window,
        renew: boolean = true
    ): Promise<IToken<T>> {

        /*
        Check if we have an existing session. If that session is valid return it
         */
        const existingSession = this.restoreSession(provider, storage);
        if (existingSession) {
            const isSessionValid = provider.validateSession(existingSession);
            if (isSessionValid) {
                return new Promise<any>((resolve, reject) => {
                    resolve({
                        session: existingSession,
                        renewed: false
                    });
                });
            }
        }

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
            localWindow.addEventListener('message', (event: MessageEvent) => {
                const origin = provider.getOrigin()
                if (origin && event.origin !== origin) {
                    return
                }
                storage.setItem(requestKey, event.data)
                let reply: string = 'done'
                // @ts-ignore
                event.source.postMessage(reply, event.origin)
            })
        }
        return new Promise<any>(async (resolve, reject) => {
            // Poll for when the is closed
            const checkWindow = async (loginWindow: Window | null) => {
                if (!loginWindow) {
                    reject(
                        new Error(
                            `Login window couldn't be opened, check popup permissions in the browser`
                        )
                    )
                    return
                }

                // If window is still open check again later
                if (!loginWindow.closed) {
                    setTimeout(() => checkWindow(loginWindow), 100)
                    return
                }

                const redirectUrl = storage.getItem(requestKey)
                storage.removeItem(requestKey)

                // Window was closed, but never reached the redirect.html due to user closing window or network error during authentication
                if (typeof redirectUrl !== 'string' || redirectUrl.length === 0) {
                    reject(
                        new Error(
                            `Login window was closed by the user or authentication was incomplete and never reached final redirect page.`
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
                const [err] = await to(provider.getAccessTokenAsync(session));
                if (err) {
                    reject(err);
                    return;
                }
                storage.setItem(sessionKey, JSON.stringify(session))
                resolve({
                    session: existingSession,
                    renewed: true
                });
            }
            await to(checkWindow(loginWindow))
        });
    }


    restoreSession<T extends Session>(provider: IProvider<T>, storage: Storage = window.localStorage): T | undefined {
        const sessionString = storage.getItem(sessionKey)
        if (typeof sessionString !== 'string' || sessionString.length === 0) {
            storage.removeItem(sessionKey);
            return undefined
        }
        try {
            return JSON.parse(sessionString)
        } catch (e) {
            storage.removeItem(sessionKey);
            console.log("Session is not valid");
        }
        return undefined;
    }

    invalidateSession<T extends Session>(provider: IProvider<T>, storage: Storage = window.localStorage): Promise<any> {
        const session = this.restoreSession(provider, storage);
        if (!session) {
            return Promise.resolve();
        }

        if (provider.signOut) {
            return provider.signOut(session).then(() => {
                    storage.removeItem(sessionKey)
                }
            )
        }

        storage.removeItem(sessionKey);
        return Promise.resolve();
    }

    hasSession(storage: Storage = window.localStorage): boolean {
        const sessionString = storage.getItem(sessionKey)
        return (typeof sessionString === 'string' && sessionString.length > 0)
    }
}

export default new ReactSimpleAuth();

function guid(): string {
    let d = new Date().getTime()
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c: string) {
        let r = (d + Math.random() * 16) % 16 | 0
        d = Math.floor(d / 16)
        return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16)
    })
}
