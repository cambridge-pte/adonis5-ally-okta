import type { ApplicationContract } from '@ioc:Adonis/Core/Application'
export default class OktaDriverProvider {
  constructor(protected app: ApplicationContract) {}

  public async boot() {
    const Ally = this.app.container.resolveBinding('Adonis/Addons/Ally')
    const { OktaDriver } = await import('../src/adonis5-ally-okta')

    Ally.extend('okta', (_, __, config, ctx) => {
      return new OktaDriver(ctx, config)
    })
  }
}
