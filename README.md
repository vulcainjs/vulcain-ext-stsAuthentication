# Extension to provide openid authentication

> This extension has been tested with [IdentityServer](https://hub.docker.com/r/identitycontrib/identityserver/)

## How to use it

### Start a identity server instance

See this [sample](https://github.com/IdentityServer/IdentityServer4.Samples/tree/release/Docker) to start an instance with docker

### Install package with

```js
npm install vulcain-ext-stsauthentication --save
```

And import it in your index.js vulcain project file.

```js
import { StsAuthentication } from 'vulcain-ext-stsauthentication';
```

### Declare an environment variable

exemple

```js
vulcainStsAuthority="http://localhost:5001"
```
