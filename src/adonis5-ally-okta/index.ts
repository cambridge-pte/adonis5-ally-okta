/*
|--------------------------------------------------------------------------
| Ally Oauth driver
|--------------------------------------------------------------------------
|
| This is a dummy implementation of the Oauth driver. Make sure you
|
| - Got through every line of code
| - Read every comment
|
*/

import type {
  AllyUserContract,
  ApiRequestContract,
  LiteralStringUnion,
} from '@ioc:Adonis/Addons/Ally'
import type { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { Oauth2Driver, ApiRequest, RedirectRequest } from '@adonisjs/ally/build/standalone'
const crypto = require('crypto')
/**
 * Define the access token object properties in this type. It
 * must have "token" and "type" and you are free to add
 * more properties.
 *
 * ------------------------------------------------
 * Change "YourDriver" to something more relevant
 * ------------------------------------------------
 */
export type OktaDriverAccessToken = {
  token: string
  type: 'bearer'
}

/**
 * Define a union of scopes your driver accepts. Here's an example of same
 * https://github.com/adonisjs/ally/blob/develop/adonis-typings/ally.ts#L236-L268
 *
 * ------------------------------------------------
 * Change "YourDriver" to something more relevant
 * ------------------------------------------------
 */
export type OktaDriverScopes =
  | 'openid'
  | 'email'
  | 'profile'
  | 'address'
  | 'phone'
  | 'offline_access'
  | 'groups'
/**
 * Define the configuration options accepted by your driver. It must have the following
 * properties and you are free add more.
 *
 * ------------------------------------------------
 * Change "YourDriver" to something more relevant
 * ------------------------------------------------
 */
export type OktaDriverConfig = {
  driver: 'okta'
  clientId: string
  clientSecret: string
  callbackUrl: string
  authorizeUrl: string
  accessTokenUrl: string
  userInfoUrl: string
  scopes: LiteralStringUnion<OktaDriverScopes>
  responseType: string
}

/**
 * Driver implementation. It is mostly configuration driven except the user calls
 *
 * ------------------------------------------------
 * Change "YourDriver" to something more relevant
 * ------------------------------------------------
 */
export class OktaDriver extends Oauth2Driver<OktaDriverAccessToken, OktaDriverScopes> {
  /**
   * The URL for the redirect request. The user will be redirected on this page
   * to authorize the request.
   */
  protected authorizeUrl = ''

  /**
   * The URL to hit to exchange the authorization code for the access token
   */
  protected accessTokenUrl = ''

  /**
   * The URL to hit to get the user details
   */
  protected userInfoUrl = ''

  /**
   * The param name for the authorization code. Read the documentation of your oauth
   * provider and update the param name to match the query string field name in
   * which the oauth provider sends the authorization_code post redirect.
   */
  protected codeParamName = 'code'

  /**
   * The param name for the error. Read the documentation of your oauth provider and update
   * the param name to match the query string field name in which the oauth provider sends
   * the error post redirect
   */
  protected errorParamName = 'error'

  /**
   * Cookie name for storing the CSRF token. Make sure it is always unique. So a better
   * approach is to prefix the oauth provider name to `oauth_state` value.
   */
  protected stateCookieName = 'OktaDriver_oauth_state'

  /**
   * Parameter name to be used for sending and receiving the state from.
   * Read the documentation of your oauth provider and update the param
   * name to match the query string used by the provider for exchanging
   * the state.
   */
  protected stateParamName = 'state'

  /**
   * Parameter name for sending the scopes to the oauth provider.
   */
  protected scopeParamName = 'scope'

  /**
   * The separator indentifier for defining multiple scopes
   */
  protected scopesSeparator = ' '

  constructor(ctx: HttpContextContract, public config: OktaDriverConfig) {
    super(ctx, config)
    /**
     * Extremely important to call the following method to clear the
     * state set by the redirect request.
     *
     * DO NOT REMOVE THE FOLLOWING LINE
     */
    this.loadState()
  }

  /**
   * Optionally configure the authorization redirect request. The actual request
   * is made by the base implementation of "Oauth2" driver and this is a
   * hook to pre-configure the request.
   */

  protected configureRedirectRequest(request: RedirectRequest<OktaDriverScopes>) {
    const generateToken = (prefix: string, length = 16) => {
      return prefix + crypto.randomBytes(length).toString('hex')
    }

    const state = generateToken('state-')
    const nonce = generateToken('nonce-')

    request.param('scope', this.config.scopes)
    request.param('state', state)
    request.param('response_type', this.config.responseType)
    request.param('nonce', nonce)
    request.param('redirect_uri', this.config.callbackUrl)

    return request
  }
  /**
   * Returns the HTTP request with the authorization header set
   */
  protected getAuthenticatedRequest(url: string, token?: string) {
    const request = this.httpClient(url)
    request.header('Authorization', `Bearer ${token}`)
    request.header('Accept', 'application/json')
    request.parseAs('json')
    return request
  }

  /**
   * Fetches the user info from the Google API
   */
  protected async getUserInfo(token: string, callback?: (request: ApiRequestContract) => void) {
    const request = this.getAuthenticatedRequest(this.config.userInfoUrl || this.userInfoUrl, token)

    if (typeof callback === 'function') {
      callback(request)
    }

    const body = await request.get()

    return {
      id: body.sub,
      nickName: body.name,
      name: body.name,
      email: body.preferred_username,
      avatarUrl: body.picture,
      emailVerificationState: body.email_verified ? ('verified' as const) : ('unverified' as const),
      original: body,
    }
  }

  /**
   * Optionally configure the access token request. The actual request is made by
   * the base implementation of "Oauth2" driver and this is a hook to pre-configure
   * the request
   */
  protected configureAccessTokenRequest(request: ApiRequest) {
    const code = this.getCode()
    const auth = Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString(
      'base64'
    )

    request.headers = {
      'content-type': 'application/x-www-form-urlencoded;charset=utf-8',
      'authorization': `Basic ${auth}`,
    }

    request.fields = {
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: this.config.callbackUrl,
    }

    return request
  }
  /**
   * Update the implementation to tell if the error received during redirect
   * means "ACCESS DENIED".
   */
  public accessDenied() {
    return this.ctx.request.input('error') === 'user_denied'
  }
  /**
   * Get the user details by query the provider API. This method must return
   * the access token and the user details both. Checkout the google
   * implementation for same.
   *
   * https://github.com/adonisjs/ally/blob/develop/src/Drivers/Google/index.ts#L191-L199
   */
  public async user(
    callback?: (request: ApiRequest) => void
  ): Promise<AllyUserContract<OktaDriverAccessToken>> {
    const accessToken = await this.accessToken()
    const user = await this.getUserInfo(accessToken.token, callback)

    return {
      ...user,
      token: accessToken,
    }
  }

  public async userFromToken(
    accessToken: string,
    callback?: (request: ApiRequest) => void
  ): Promise<AllyUserContract<{ token: string; type: 'bearer' }>> {
    const user = await this.getUserInfo(accessToken, callback)

    return {
      ...user,
      token: { token: accessToken, type: 'bearer' as const },
    }
  }
}
