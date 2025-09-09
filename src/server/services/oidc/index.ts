import debug from 'debug';

import { createContextForInteractionDetails } from '@/libs/oidc-provider/http-adapter';
import { OIDCProvider } from '@/libs/oidc-provider/provider';

import { getOIDCProvider } from './oidcProvider';

const log = debug('lobe-oidc:service');

export class OIDCService {
  private provider: OIDCProvider;

  constructor(provider: OIDCProvider) {
    this.provider = provider;
  }
  static async initialize() {
    const provider = await getOIDCProvider();

    return new OIDCService(provider);
  }

  async getInteractionDetails(uid: string) {
    const { req, res } = await createContextForInteractionDetails(uid);
    return this.provider.interactionDetails(req, res);
  }

  async getInteractionResult(uid: string, result: any) {
    const { req, res } = await createContextForInteractionDetails(uid);
    return this.provider.interactionResult(req, res, result);
  }

  async finishInteraction(uid: string, result: any) {
    const { req, res } = await createContextForInteractionDetails(uid);
    return this.provider.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
  }

  async findOrCreateGrants(accountId: string, clientId: string, existingGrantId?: string) {
    // 2. 查找或创建 Grant 对象
    let grant;
    if (existingGrantId) {
      // 如果之前的交互步骤已经关联了 Grant
      grant = await this.provider.Grant.find(existingGrantId);
      log('Found existing grantId: %s', existingGrantId);

      // 如果找到的 Grant 归属的账户与当前账户不一致，则丢弃旧的 Grant，创建新的
      // 解决切换账号后继续授权导致的 "accountId mismatch" 问题
      if (grant && (grant as any).accountId && (grant as any).accountId !== accountId) {
        log(
          'Existing grant accountId mismatch (grant.accountId=%s, current=%s), ignore and recreate',
          (grant as any).accountId,
          accountId,
        );
        grant = undefined;
      }
    }

    if (!grant) {
      // 如果没有找到或没有 existingGrantId，则创建新的
      grant = new this.provider.Grant({
        accountId: accountId,
        clientId: clientId,
      });
      log('Created new Grant for account %s and client %s', accountId, clientId);
    }

    return grant;
  }

  async getClientMetadata(clientId: string) {
    const client = await this.provider.Client.find(clientId);
    return client?.metadata();
  }
}

export { getOIDCProvider } from './oidcProvider';
