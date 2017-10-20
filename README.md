# Extension to provide openid authentication

> This extension will be tested with [IdentityServer](https://hub.docker.com/r/identitycontrib/identityserver/)

## How to use it

### Start a identity server instance

See this [sample](https://github.com/IdentityServer/IdentityServer4.Samples/tree/release/Docker) to start an instance with docker

### Install package with

```js
npm install vulcain-ext-express --save
```

### Declare an environment variable

exemple

```js
vulcainStsAuthority="http://localhost:5001"
```

### Create a new adapter extending ExpressAdapter which will replace the default adapter

```js
import { ExpressAdapter } from 'vulcain-ext-express';

// Declare your new adapter before running application
@Injectable(LifeTime.Singleton, DefaultServiceNames.ServerAdapter )
class MyAdapter extends ExpressAdapter {
    initializeRoutes(express) {
        // Add express initialization here
    }
}

// MyAdapter will be use automatically
let app = new ApplicationBuilder('Domain')
    .run();
```
