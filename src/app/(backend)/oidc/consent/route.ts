import debug from 'debug';
import { NextRequest, NextResponse } from 'next/server';

import { OIDCService } from '@/server/services/oidc';
import { getUserAuth } from '@/utils/server/auth';
import { correctOIDCUrl } from '@/utils/server/correctOIDCUrl';

const log = debug('lobe-oidc:consent');

export async function POST(request: NextRequest) {
  log('Received POST request for /oidc/consent, URL: %s', request.url);
  try {
    const formData = await request.formData();
    const consent = formData.get('consent') as string;
    const uid = formData.get('uid') as string;

    log('POST /oauth/consent - uid=%s, choice=%s', uid, consent);

    const oidcService = await OIDCService.initialize();

    let details;
    try {
      details = await oidcService.getInteractionDetails(uid);
      log(
        'Interaction details found - prompt=%s, client=%s',
        details.prompt.name,
        details.params.client_id,
      );
    } catch (error) {
      log(
        'Error: Interaction details not found - %s',
        error instanceof Error ? error.message : 'unknown error',
      );
      if (error instanceof Error && error.message.includes('interaction session not found')) {
        return NextResponse.json(
          {
            error: 'invalid_request',
            error_description:
              'Authorization session expired or invalid, please restart the authorization flow',
          },
          { status: 400 },
        );
      }
      throw error;
    }

    const { prompt } = details;
    let result;
    let internalRedirectUrlString: string | undefined;
    if (consent === 'accept') {
      log(`User accepted the request.`);
      const { userId } = await getUserAuth();
      log('Obtained userId: %s', userId);

      if (!userId) {
        log('No userId found in auth context, abort consent with 401');
        return NextResponse.json(
          {
            error: 'not_authenticated',
            error_description: 'User is not authenticated',
          },
          { status: 401 },
        );
      }

      if (details.prompt.name === 'login') {
        log(`Handling 'login' prompt`);
        result = { login: { accountId: userId, remember: true } };
        log('Interaction Result (login): %O', result);
        internalRedirectUrlString = await oidcService.getInteractionResult(uid, result);
      } else {
        log(`Handling 'consent' prompt`);

        // 1. 获取必要的 ID
        const clientId = details.params.client_id as string;
        log('Consent flow context: %o', {
          clientId,
          detailsGrantId: details.grantId,
          promptName: details.prompt?.name,
        });

        // 2. 查找或创建 Grant 对象
        const grant = await oidcService.findOrCreateGrants(userId!, clientId, details.grantId);

        // 3. 将用户同意的 scopes 和 claims 添加到 Grant 对象
        const missingOIDCScope = (prompt.details.missingOIDCScope as string[]) || [];
        if (missingOIDCScope) {
          grant.addOIDCScope(missingOIDCScope.join(' '));
          log('Added OIDC scopes to grant: %s', missingOIDCScope.join(' '));
        }
        const missingOIDCClaims = (prompt.details.missingOIDCClaims as string[]) || [];
        if (missingOIDCClaims) {
          grant.addOIDCClaims(missingOIDCClaims);
          log('Added OIDC claims to grant: %s', missingOIDCClaims.join(' '));
        }

        const missingResourceScopes =
          (prompt.details.missingResourceScopes as Record<string, string[]>) || {};
        if (missingResourceScopes) {
          for (const [indicator, scopes] of Object.entries(missingResourceScopes)) {
            grant.addResourceScope(indicator, scopes.join(' '));
            log('Added resource scopes for %s to grant: %s', indicator, scopes.join(' '));
          }
        }

        // 4. 保存 Grant 对象以获取其 jti (grantId)
        const newGrantId = await grant.save();
        log('Saved grant with ID: %s', newGrantId);

        // 5. 检测 provider session 的 accountId 与当前用户是否一致
        const providerSessionAccountId = (details as any)?.session?.accountId as string | undefined;
        log('Provider session accountId: %s; Current userId: %s', providerSessionAccountId, userId);
        if (providerSessionAccountId && providerSessionAccountId !== userId) {
          log(
            "Provider session's accountId (%s) != current userId (%s). Finishing with login+consent to resync.",
            providerSessionAccountId,
            userId,
          );

          result = {
            consent: { grantId: newGrantId },
            login: { accountId: userId, remember: true },
          };
          log('Interaction Result (login+consent): %O', result);
          // Use interactionResult to obtain redirect URL string
          internalRedirectUrlString = await oidcService.getInteractionResult(uid, result as any);
        } else {
          // 正常 consent 提交流程
          result = { consent: { grantId: newGrantId } };
          log('Interaction Result (consent): %O', result);
          internalRedirectUrlString = await oidcService.getInteractionResult(uid, result);
        }
      }
      log('User %s the authorization', consent);
    } else {
      log('User rejected the request');
      result = {
        error: 'access_denied',
        error_description: 'User denied the authorization request',
      };
      log('Interaction Result (rejected): %O', result);
      internalRedirectUrlString = await oidcService.getInteractionResult(uid, result);
      log('User %s the authorization', consent);
    }

    log('OIDC Provider internal redirect URL string: %s', internalRedirectUrlString);

    if (!internalRedirectUrlString) {
      log('ERROR: internalRedirectUrlString is empty or undefined, cannot continue');
      return NextResponse.json(
        {
          error: 'server_error',
          error_description: 'Internal redirect URL is missing',
        },
        { status: 500 },
      );
    }

    let finalRedirectUrl;
    try {
      // If provider returned a relative path, construct with request origin
      const redirectUrl = new URL(internalRedirectUrlString, request.nextUrl.origin);
      finalRedirectUrl = correctOIDCUrl(request, redirectUrl);
    } catch (e) {
      log('Error parsing redirect URL: %O', e);
      return NextResponse.json(
        {
          error: 'server_error',
          error_description: 'Invalid redirect URL from provider',
        },
        { status: 500 },
      );
    }

    log('Final redirect URL: %s', finalRedirectUrl.toString());

    return NextResponse.redirect(finalRedirectUrl, {
      headers: request.headers,
      status: 303,
    });
  } catch (error) {
    log('Error processing consent: %s', error instanceof Error ? error.message : 'unknown error');
    console.error('Error processing consent:', error);
    return NextResponse.json(
      {
        error: 'server_error',
        error_description: 'Error processing consent',
      },
      { status: 500 },
    );
  }
}
