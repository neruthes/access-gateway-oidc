// gateway.js
import express from 'express';
import session from 'express-session';
import { createProxyMiddleware } from 'http-proxy-middleware';
import fs from 'fs/promises';
import path from 'path';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import fetch from 'node-fetch';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const configPath = process.argv[2];
if (!configPath) throw new Error('Usage: node gateway.js <config.json>');

const config = JSON.parse(await fs.readFile(configPath, 'utf8'));
const PORT = process.env.PORT || config.port || 18562;

app.set('trust proxy', 1);
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false }
}));

const ssoAuthorities = config.ssoAuthorities;
const placeholderHtml = await fs.readFile(path.resolve(__dirname, config.placeholderPage), 'utf8');

function wildcardMatch(str, pattern) {
    const regex = new RegExp('^' + pattern.split('*').map(s => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
    return regex.test(str);
}

function findAccessControl(basePath) {
    let dir = path.dirname(basePath);
    const tried = new Set();
    return async function search() {
        while (!tried.has(dir)) {
            tried.add(dir);
            try {
                const acl = JSON.parse(await fs.readFile(path.join(dir, '.htaccess.json'), 'utf8'));
                return acl;
            } catch (e) {
                dir = path.resolve(dir, '..');
                if (dir === '/') break;
            }
        }
        return null;
    }
}

function createOIDCFlow(sso) {
    const jwks = createRemoteJWKSet(new URL(sso.jwks_uri));

    console.log('[jwks]');
    console.log(jwks);
    return {
        async verifyJWT(token) {
            const { payload } = await jwtVerify(token, jwks, {
                issuer: sso.issuer,
                audience: sso.client_id,
            });
            console.log('[payload]');
            console.log(payload);
            return payload;
        },

        async exchangeCode(code, codeVerifier, redirectUri) {
            console.log('[URLSearchParams]');
            console.log(URLSearchParams);
            const params = new URLSearchParams({
                grant_type: 'authorization_code',
                code,
                redirect_uri: redirectUri,
                client_id: sso.client_id,
                code_verifier: codeVerifier,
            });

            const res = await fetch(sso.token_endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: params.toString(),
            });
            if (!res.ok) throw new Error('Token exchange failed');
            return await res.json();
        },
    }
}

const oidcClients = Object.fromEntries(
    ssoAuthorities.map(sso => [sso.issuer, createOIDCFlow(sso)])
);

function generatePKCE() {
    const codeVerifier = crypto.randomBytes(32).toString('hex');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    return { codeVerifier, codeChallenge };
}

app.get('/callback', async (req, res) => {
    try {
        const { code, state } = req.query;
        const sessionData = req.session[state];
        if (!sessionData) return res.status(403).send('Invalid CSRF or state');

        const { redirectUri, ssoIssuer, codeVerifier, originalUrl } = sessionData;
        const oidc = oidcClients[ssoIssuer];
        const tokenSet = await oidc.exchangeCode(code, codeVerifier, redirectUri);
        const user = await oidc.verifyJWT(tokenSet.id_token);

        req.session.user = user;
        res.redirect(originalUrl);
    } catch (err) {
        console.error(err);
        res.status(500).send('OIDC callback failed');
    }
});

app.use(async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        let user;
        if (token) {
            for (const sso of ssoAuthorities) {
                try {
                    user = await oidcClients[sso.issuer].verifyJWT(token);
                    break;
                } catch { }
            }
        } else if (req.session.user) {
            user = req.session.user;
        }


        // New code
        if (!user) {
            const redirectUri = `https://${config.mapping.host}/callback`;
            const stateMap = {};
            const links = ssoAuthorities.map(sso => {
                const { codeVerifier, codeChallenge } = generatePKCE();
                const state = crypto.randomUUID();

                req.session[state] = {
                    codeVerifier,
                    redirectUri,
                    ssoIssuer: sso.issuer,
                    originalUrl: req.originalUrl,
                };

                const authUrl = new URL(sso.authorization_endpoint);
                authUrl.searchParams.set('response_type', 'code');
                authUrl.searchParams.set('client_id', sso.client_id);
                authUrl.searchParams.set('redirect_uri', redirectUri);
                authUrl.searchParams.set('scope', 'openid email');
                authUrl.searchParams.set('state', state);
                authUrl.searchParams.set('code_challenge', codeChallenge);
                authUrl.searchParams.set('code_challenge_method', 'S256');

                return `<li><a href="${authUrl.toString()}">${sso.name || sso.issuer}</a></li>`;
            }).join('\n');

            return res.status(401).send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Choose SSO</title></head>
<body><h1>Select a login provider</h1><ul>${links}</ul></body></html>`);
        };


        // Old code
        if (!user) {
            const sso = ssoAuthorities[0];
            const { codeVerifier, codeChallenge } = generatePKCE();
            const state = crypto.randomUUID();
            const redirectUri = `https://${config.mapping.host}/callback`;

            req.session[state] = {
                codeVerifier,
                redirectUri,
                ssoIssuer: sso.issuer,
                originalUrl: req.originalUrl,
            };

            const authUrl = new URL(sso.authorization_endpoint);
            authUrl.searchParams.set('response_type', 'code');
            authUrl.searchParams.set('client_id', sso.client_id);
            authUrl.searchParams.set('redirect_uri', redirectUri);
            authUrl.searchParams.set('scope', 'openid email');
            authUrl.searchParams.set('state', state);
            authUrl.searchParams.set('code_challenge', codeChallenge);
            authUrl.searchParams.set('code_challenge_method', 'S256');

            console.log(authUrl.toString());
            return res.redirect(authUrl.toString());
        }

        // access control
        const acl = await findAccessControl(req.path)();
        if (acl?.pattern && !wildcardMatch(user.email || user.sub, acl.pattern)) {
            return res.status(403).send('Access denied');
        };

        req.user = user;
        next();
    } catch (e) {
        console.error(e);
        res.status(500).send('Authentication error');
    }
});

// '/{*any}', // No need this string when middleware applies globally?
app.use((req, res, next) => {
    if (req.method !== 'GET') return res.status(405).send('Method Not Allowed');
    if (!req.originalUrl.startsWith('/') || req.originalUrl.includes('..')) return res.status(400).send('Bad URL');
    // let target = config.mapping.src + req.originalUrl; // I have to put URL together myself?
    let target = config.mapping.src; // I have to put URL together myself?
    console.log(`createProxyMiddleware :: target = ${target}`);
    return createProxyMiddleware({
        target,
        changeOrigin: false,
        selfHandleResponse: false,
        proxyTimeout: 30000,
        onProxyReq(proxyReq, req) {
            proxyReq.setHeader('X-User-Email', req.user?.email || '');
        },
    })(req, res, next);
});

app.use((req, res) => {
    res.status(403).send(placeholderHtml);
});

app.listen(PORT, '127.0.0.1', () => {
    console.log(`OIDC Gateway listening on http://127.0.0.1:${PORT}`);
});
