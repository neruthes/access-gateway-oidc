# access-gateway-oidc


Web access control gateway with OIDC. WIP.

Check Authorization header JWT; if invalid, send user to SSO.

This is a reverse proxy gateway script that works as the bacon in a proxy-chain sandwich.

Suppose you use default port 18562, browser requests often go through this chain:

- nginx:443 (from CDN or browser)
- node:18562 (from `nginx`)
- nginx:22222 (from `node`) (This is the real web server that reads your filesystem)


Tested with a self-hosted Zitadel instance as IdP.
Also tested with an AuthMatter instance.
Both worked perfectly.


## Installation

Clone this repo.




## Gateway Config

- Make a config JSON file, like `examples/config.json`.
- Start daemon `node src/index.js examples/config.json`.
- Set up both sides of the mapping; usually two `server` blocks in Nginx config.



## SSO Center Config

- Create app and set client_id and redirect_uris.
- Prefer PKCE to eliminate the need for client_secret.
- Make sure to have proper JWT support.



## Possible Future Plans

- Support requiring particular roles from OIDC OP to allow access certain URL patterns.




## Copyright

Copyright (c) 2025 Neruthes.

Released with the GNU GPL 2.0 license.


