import { getEnvVariable } from "@stackframe/stack-shared/dist/utils/env";
import { StackAssertionError } from "@stackframe/stack-shared/dist/utils/errors";
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

function getCatapaApiUrl(): string {
  return getEnvVariable("STACK_CATAPA_API_URL") || "https://api-apps.catapa.com";
}

/**
 * CATAPA uses a tenant header/query/body param to identify the tenant.
 * The super.getAccessToken method won't work correctly because it doesn't know the tenant.
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

    return validateUserInfo({
      accountId: `${userInfo.username}@${tenant}:catapa`,
      displayName: userInfo.employee?.name ?? userInfo.username,
      email: userInfo.email,
      profileImageUrl: employeeId ? await this.getProfileImageUrl(employeeId, tokenSet.accessToken) : null,
      // In CATAPA, same email can be used in multiple tenants.
      // We deliberately don't verify the email here so that stackauth does not use it as identifier.
      // So we rely only on the accountId to identify the user.
      emailVerified: false,
    });
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
    const search = new URLSearchParams({ query: `identificationNumberIn:${employeeId}` });
    const url = `${getCatapaApiUrl()}/core/v1/employees?${search.toString()}`;

    const listRes = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Tenant: tenant ?? '',
      },
    });
    if (!listRes.ok) return null;

    const listJson: any = await listRes.json();
    const employee = Array.isArray(listJson?.content) ? listJson.content[0] : null;
    return employee?.photo?.url;
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
