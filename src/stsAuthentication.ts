import { IAuthenticationStrategy, IAuthorizationPolicy, ConfigurationProperty, IDynamicProperty, Inject, DefaultServiceNames, System, IRequestContext, Injectable, LifeTime, DynamicConfiguration, UserContextData } from "vulcain-corejs";
import { Constants } from "./constants";
const unirest = require('unirest');
const jwt = require('jsonwebtoken');
const jwks = require('jwks-rsa');
const ms = require('ms');

@Injectable(LifeTime.Singleton, DefaultServiceNames.AuthenticationStrategy )
export class StsAuthentication implements IAuthenticationStrategy {

    public readonly name = "bearer";

    @ConfigurationProperty(Constants.TOKEN_STS_AUTHORITY, "string")
    private authority: IDynamicProperty<string>;
    private userInfoEndpoint: string;
    private readonly openidConfig: string = '/.well-known/openid-configuration';
    private jwksConfig = {
        cache: true,
        cacheMaxEntries: 5,
        cacheMaxAge: ms('8h'),
        strictssl: false, // TODO: test env to enforce ssl in production
        jwksUri: undefined
    };
    private signingKey: string;
    private jwksClient: { getSigningKey(kid: string, callback: (err: Error, key: { publicKey: string, rsaPublicKey: string }) => void) };

    constructor() {
        this.authority = DynamicConfiguration.getChainedConfigurationProperty<string>(Constants.TOKEN_STS_AUTHORITY, 'http://localhost:5100');
        System.log.info(null, () => `using ${this.authority.value} as STS authority`);
        this.initializeRsaSigninKey();
    }

    private ensureInitialized(): Promise<boolean> {
        return new Promise((resolve, reject) => {
            if (this.jwksClient) {
                resolve(true);
            } else {
                this.initializeRsaSigninKey().then(_ => resolve(true), rej => reject(rej));
            }
        });
    }

    private initializeRsaSigninKey(): Promise<string> {
        return new Promise((resolve, reject) => {
            const openIdConfigUrl = `${this.authority.value}/.well-known/openid-configuration`;
            // TODO command
            const oidcConfig = unirest.get(openIdConfigUrl).as.json((res) => {
                if (res.error) {
                    reject(res.error);
                } else if (res.status >= 400) {
                    reject(res);
                } else {
                    this.jwksConfig.jwksUri = res.body.jwks_uri;
                    this.jwksClient = jwks(this.jwksConfig);
                    resolve(this.jwksConfig.jwksUri);
                }
            });
        });
    }

    private ensureUserInfoEndpointLoaded() {
        return new Promise<boolean>((resolve, reject) => {
            if (this.userInfoEndpoint) {
                resolve(true);
            } else {
                const openIdConfigUrl = `${this.authority.value}/.well-known/openid-configuration`;
                unirest.get(openIdConfigUrl).as.json(res => {
                    if (res.error) {
                        reject(res.error);
                    } else if (res.status >= 400) {
                        reject(res);
                    } else {
                        this.userInfoEndpoint = res.body.userinfo_endpoint;
                        resolve(true);
                    }
                });
            }
        });
    }

    private async getUserInfo(accessToken: string) {
        await this.ensureUserInfoEndpointLoaded()
            .catch(err => {
                System.log.error(null, err, () => 'Error getting STS user info endpoint');
            });

        return new Promise<any>((resolve, reject) => {
            unirest.get(this.userInfoEndpoint).headers({ authorization: `Bearer ${accessToken}` }).as.json(res => {
                if (res.status >= 400) {
                    reject(res);
                } else {
                    resolve(res.body);
                }
            });

        });
    }

    verifyToken(ctx: IRequestContext, accessToken: string, tenant: string): Promise<UserContextData> {
        return new Promise((resolve, reject) => {
            if (!accessToken) {
                reject("You must provide a valid token");
                return;
            }
            let options: any = {
                "issuer": [this.authority.value],
                // "audience": "patient-highlights" //TODO: get service name as defined in STS resource manager
            };

            const decodedToken = jwt.decode(accessToken, { complete: true });

            this.ensureInitialized().then(() => {
                this.jwksClient.getSigningKey(decodedToken.header.kid, (err, key) => {
                    if (err) {
                        reject({ error: err, message: `Unable to resolve RSA public key from kid: ${decodedToken.header.kid}` });
                        return;
                    }
                    const signingKey = key.publicKey || key.rsaPublicKey;

                    jwt.verify(accessToken, signingKey, options, async (err, decodedToken) => {
                        if (err) {
                            reject({ error: err, message: "Invalid JWT token" });
                        } else {
                            // get user info from STS
                            let user = await this.getUserInfo(accessToken);
                            user.scopes = [
                                ...decodedToken.scope,
                                ...decodedToken.role
                            ];
                            resolve(user);
                        }
                    });
                });
            })
                .catch(reject);

        });
    }
}