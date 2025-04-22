# access-gateway-oidc


Web access control gateway with OIDC. WIP.

Check Authorization header JWT; if invalid, send user to SSO.

This is a reverse proxy gateway script that works as the bacon in a proxy-chain sandwich.

Suppose you use default port 18562, browser requests often go through this chain:

- nginx:443 (from CDN or browser)
- node:18562 (from `nginx`)
- nginx:22222 (from `node`) (This is the real web server that reads your filesystem)





## Installation

Clone this repo.




## Configuration

- Make a config JSON file, like `examples/config.json`.
- Start daemon `node src/index.js examples/config.json`.
- Set up both sides of the mapping; usually two `server` blocks in Nginx config.



## Copyright

Copyright (c) 2025 Neruthes.

Released with the GNU GPL 2.0 license.
