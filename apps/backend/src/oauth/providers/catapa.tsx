import { KnownErrors } from "@stackframe/stack-shared";
import { getEnvVariable } from "@stackframe/stack-shared/dist/utils/env";
import { StackAssertionError, StatusError, captureError } from "@stackframe/stack-shared/dist/utils/errors";
import { CallbackParamsType, TokenSet as OIDCTokenSet } from "openid-client";
import { OAuthUserInfo, validateUserInfo } from "../utils";
import { OAuthBaseProvider, TokenSet } from "./base";

type CatapaUserInfo = {
  id: string,
  username: string,
  email?: string,
  employee?: {
    id: string,
    name: string,
  },
};

type CatapaEmployeeDetail = {
  id: string,
  employee: {
    photo?: {
      url: string,
    },
  },
}

function getCatapaApiUrl(): string {
  return getEnvVariable("STACK_CATAPA_API_URL") || "https://api-apps.catapa.com";
}

/**
 * CATAPA OAuth provider.
 *
 * CATAPA uses a tenant header/query/body param to identify the tenant.
 *
 * We override getCallback to pass the tenant to the token endpoint.
 *
 * But the super.getAccessToken method won't work correctly because it doesn't know the tenant.
 * Currently we can't infer the tenant from the refresh token.
 * However, for the login use case, it seems that super.getAccessToken method is not used.
 */
export class CatapaProvider extends OAuthBaseProvider {
  private constructor(
    ...args: ConstructorParameters<typeof OAuthBaseProvider>
  ) {
    super(...args);
  }

  static async create(options: {
    clientId: string,
    clientSecret: string,
  }) {
    return new CatapaProvider(...await OAuthBaseProvider.createConstructorArgs({
      issuer: "https://catapa.com",
      authorizationEndpoint: getEnvVariable("STACK_CATAPA_AUTHORIZATION_ENDPOINT") || "https://accounts-apps.catapa.com/oauth2/authorize",
      tokenEndpoint: getEnvVariable("STACK_CATAPA_TOKEN_ENDPOINT") || "https://api-apps.catapa.com/oauth/token",
      userinfoEndpoint: `${getCatapaApiUrl()}/v1/users/me`,
      redirectUri: getEnvVariable("NEXT_PUBLIC_STACK_API_URL") + "/api/v1/auth/oauth/callback/catapa",
      baseScope: "all",
      tokenEndpointAuthMethod: "client_secret_basic",
      noPKCE: true,
      ...options,
    }));
  }

  /**
   * CATAPA OAuth callback.
   *
   * Reimplementation of the base getCallback method with additional tenant body param.
   * The tenant is inferred from the callback params.
   */
  async getCallback(options: {
    callbackParams: CallbackParamsType,
    codeVerifier: string,
    state: string,
  }): Promise<{ userInfo: OAuthUserInfo, tokenSet: TokenSet }> {
    let tokenSet;
    const params = [
      this.redirectUri,
      options.callbackParams,
      {
        code_verifier: this.noPKCE ? undefined : options.codeVerifier,
        state: options.state,
      },
      {
        exchangeBody: {
          tenant: options.callbackParams.tenant,
        },
      }
    ] as const;
    try {
      tokenSet = await this.oauthClient.oauthCallback(...params);
    } catch (error: any) {
      if (error?.error === "invalid_grant" || error?.error?.error === "invalid_grant") {
        captureError("inner-oauth-callback", { error, params });
        throw new StatusError(400, "Inner OAuth callback failed due to invalid grant. Please try again.");
      }
      if (error?.error === 'access_denied' || error?.error === 'consent_required') {
        throw new KnownErrors.OAuthProviderAccessDenied();
      }
      if (error?.error === 'invalid_client') {
        throw new StatusError(400, `Invalid client credentials for this OAuth provider. Please ensure the configuration in the Stack Auth dashboard is correct.`);
      }
      if (error?.error === 'unauthorized_scope_error') {
        const scopeMatch = error?.error_description?.match(/Scope &quot;([^&]+)&quot; is not authorized for your application/);
        const missingScope = scopeMatch ? scopeMatch[1] : null;
        throw new StatusError(400, `The OAuth provider does not allow the requested scope${missingScope ? ` "${missingScope}"` : ""}. Please ensure the scope is configured correctly in the provider's dashboard.`);
      }
      throw new StackAssertionError(`Inner OAuth callback failed due to error: ${error}`, { params, cause: error });
    }

    if ('error' in tokenSet) {
      throw new StackAssertionError(`Inner OAuth callback failed due to error: ${tokenSet.error}, ${tokenSet.error_description}`, { params, tokenSet });
    }
    tokenSet = this.processTokenSet(this.constructor.name, tokenSet);

    return {
      userInfo: await this.postProcessUserInfo(tokenSet),
      tokenSet,
    };
  }

  async checkAccessTokenValidity(accessToken: string): Promise<boolean> {
    try {
      const userInfo = await this.getUserInfo(accessToken);
      return !!userInfo;
    } catch (e) {
      return false;
    }
  }

  async postProcessUserInfo(tokenSet: TokenSet): Promise<OAuthUserInfo> {
    const tenant = this.getTenantFromAccessToken(tokenSet.accessToken);
    const userInfo = await this.getUserInfo(tokenSet.accessToken);
    const employeeId = userInfo.employee?.id;

    // Currently GLChat does not support multiple users with the same email,
    // so we don't set the email yet and let users be identified by only their accountId.
    // We can get the email from userInfo.email once GLChat supports it.
    const email = null;

    return validateUserInfo({
      accountId: `${userInfo.username}@${tenant}:catapa`,
      displayName: userInfo.employee?.name ?? userInfo.username,
      email,
      profileImageUrl: employeeId ? await this.getProfileImageUrl(employeeId, tokenSet.accessToken) : null,
      emailVerified: !!email,
    });
  }

  private processTokenSet(providerName: string, tokenSet: OIDCTokenSet): TokenSet {
    if (!tokenSet.access_token) {
      throw new StackAssertionError(`No access token received from ${providerName}.`, { tokenSetKeys: Object.keys(tokenSet), providerName });
    }

    if (!tokenSet.expires_in) {
      captureError("processTokenSet", new StackAssertionError(`No expires_in received from OAuth provider ${providerName}. Falling back to 1h`, { tokenSetKeys: Object.keys(tokenSet) }));
    }

    return {
      accessToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token,
      accessTokenExpiredAt: tokenSet.expires_in ?
        new Date(Date.now() + tokenSet.expires_in * 1000) :
        new Date(Date.now() + 3600 * 1000), // 1h
    };
  }

  private async getUserInfo(accessToken: string): Promise<CatapaUserInfo> {
    const tenant = this.getTenantFromAccessToken(accessToken);
    const userinfoEndpoint: string = this.oauthClient.issuer.metadata.userinfo_endpoint!;
    const res = await fetch(userinfoEndpoint, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Tenant: tenant ?? '',
      },
    });
    if (!res.ok) {
      throw new StackAssertionError("Error fetching user info from CATAPA provider: Status code " + res.status, {
        hasAccessToken: !!accessToken,
        hasRefreshToken: false,
        accessTokenExpiredAt: null,
      });
    }
    return await res.json();
  }

  private async getProfileImageUrl(employeeId: string, accessToken: string): Promise<string | null> {
    if (!employeeId) return null;

    const photoUrl = await this.getEmployeePhotoUrl(employeeId, accessToken);
    if (!photoUrl) return null;

    return await this.convertPhotoUrlToBase64(photoUrl);
  }

  private async getEmployeePhotoUrl(employeeId: string, accessToken: string): Promise<string | null> {
    if (!employeeId) return null;

    const tenant = this.getTenantFromAccessToken(accessToken);
    const url = `${getCatapaApiUrl()}/core/v1/employees/${employeeId}/employee-details`;

    const listRes = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Tenant: tenant ?? '',
      },
    });
    if (!listRes.ok) return null;

    const employeeDetail = await listRes.json() as CatapaEmployeeDetail;
    return employeeDetail.employee.photo?.url ?? null;
  }

  private async convertPhotoUrlToBase64(photoUrl: string): Promise<string | null> {
    const photoRes = await fetch(photoUrl, {
      signal: AbortSignal.timeout(10000), // 10 second timeout
    });
    if (!photoRes.ok) return null;

    const mime = photoRes.headers.get("content-type") || "image/jpeg";
    const buf = Buffer.from(await photoRes.arrayBuffer());

    // Guardrail: avoid excessively large payloads
    if (buf.byteLength > 1_000_000) return null;

    const base64 = buf.toString("base64");
    return `data:${mime};base64,${base64}`;
  }

  /**
   * Get the tenant from the access token JWT payload.
   *
   * Currently only access token has tenant in the payload.
   * Refresh token does not have tenant in the payload.
   */
  private getTenantFromAccessToken(accessToken: string): string | null {
    try {
      const [, payloadB64] = accessToken.split(".");
      const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
      return payload?.tenant ?? null;
    } catch (e) {
      return null;
    }
  }
}
