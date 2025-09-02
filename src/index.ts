import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import session from 'express-session';
import { BaseClient, Issuer, generators } from 'openid-client';
import jwt, { JwtPayload } from 'jsonwebtoken';
import crypto from 'crypto';
import { getCookies } from './Cookies';
import { User } from './User';

declare module 'express-session' {
    interface SessionData {
        userinfo?: User;
        client_id?: string;
        discovery_url?: string;
        code_verifier?: string;
        [key: string]: any;
    }
}

const app = express();
const PORT = +(process.env.PORT || 3600);
const COOKIE_MAX_AGE = +(process.env.COOKIE_MAX_AGE || 860000);
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const REDIRECT_PATH = process.env.REDIRECT_PATH || '/auth/oidc/callback';
const ALLOWED_CLIENTS = (process.env.ALLOWED_CLIENTS || "").split(',').map(t => t.trim()).filter(t => t != "");

app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}));

// Generate PKCE values
const codeVerifier = generators.codeVerifier();
const codeChallenge = generators.codeChallenge(codeVerifier);

// Store OIDC clients dynamically based on discovery URL
const clients: Record<string, BaseClient> = {};

async function getClient(discoveryUrl: string, clientId: string) {
    if (!clients[discoveryUrl]) {
        const issuer = await Issuer.discover(discoveryUrl);
        console.log(`Discovered issuer: ${issuer.issuer}`);
        clients[discoveryUrl] = new issuer.Client({
            client_id: clientId,
            token_endpoint_auth_method: 'none' // Public client
        });
    }
    return clients[discoveryUrl];
}

// Ignore favicons
app.use((req, res, next) => {
    if (req.path === '/favicon.ico' || req.url.includes('favicon'))
        return res.sendStatus(404);
    next();
});

/** Builds a redirect uri from the given path */
function getRedirectUri(req: express.Request, port = PORT, path = REDIRECT_PATH): string {
    const host = req.get('host') || `localhost:${port}`;
    const protoHeader = req.headers['x-forwarded-proto'];
    const protocol = Array.isArray(protoHeader)
        ? protoHeader[0]
        : (typeof protoHeader === 'string' ? protoHeader.split(',')[0] : (req.protocol || 'http'));

    return `${protocol}://${host}${path}`;
}


// STEP 1: NGINX asks if we are authenticated with the specific discovery
app.get('/verify', async (req, res) => {
    // If we have X-OIDC headers, we are coming from a auth_request
    const client_id = req.headers['x-oidc-client-id'] as string;
    const discovery_url = req.headers['x-oidc-discovery-url'] as string;
    if (!client_id || !discovery_url) {
        console.error('Missing client_id or discovery_url', { client_id, discovery_url });
        return res.status(500).send('Missing auth_request headers');
    }

    // Make sure we are not already logged in. 
    // If we are, we are already authed.
    if (req.session && req.session.userinfo) {
        return res.status(200).send('Authorized');
    }

    // Store our internal state in a signed JWT. 
    // We will pass this as a header which NGINX can use later.
    const authContext = jwt.sign({
        cid: client_id,
        url: discovery_url,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (COOKIE_MAX_AGE / 1000)
    }, JWT_SECRET);
    res.setHeader('x-auth-context', authContext);

    console.log('user unauthorized, redirecting to the login page via 401');
    return res.status(401).send('Unauthorized');
});

app.get('/login', async (req, res) => {
    if (req.session.userinfo) {
        console.warn('User attempted to access the login page, but they are already logged in.');
        return res.status(200).send('Already logged in');
    }

    const cookies = getCookies(req);
    const authCookie = cookies['auth_context'];
    if (!authCookie)
        return res.status(400).send('You must visit /auth first via the auth_request.');

    let discovery_url = '';
    let client_id = '';

    try {
        const authContext = jwt.verify(authCookie, JWT_SECRET) as JwtPayload;
        discovery_url = authContext['url'];
        client_id = authContext['cid'];
    } catch (e) {
        console.error('failed to validate JWT', (e as Error).message);
        return res.status(400).send('Your session has most likely expired.');
    }

    // Build up the redirect url and send them off
    if (ALLOWED_CLIENTS.length > 0 && !ALLOWED_CLIENTS.includes(client_id)) {
        console.error('client_id is not on the list of allowed clients.', client_id);
        return res.status(400).send('Client ID is not allowed to use this service.');
    }
        
    const client = await getClient(discovery_url, client_id);
    const authorizationUrl = client.authorizationUrl({
        scope: 'openid profile email',
        response_type: 'code',
        redirect_uri: getRedirectUri(req),
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: req.sessionID
    });

    return res.redirect(authorizationUrl);
});

// STEP 3: OIDC will call back wiht our deets
app.get('/callback', async (req, res) => {

    // Get and immediately clear cookies
    const cookies = getCookies(req);
    const redirectPath = cookies['redirect_to'] ?? '';
    if (redirectPath) res.clearCookie('redirect_to');

    const authCookie = cookies['auth_context'];
    if (!authCookie) return res.status(400).send('You must visit /auth first via the auth_request.');
    res.clearCookie('auth_context');

    // Get the discovery from the auth token
    let discovery_url = '';
    let client_id = '';
    try {
        const authContext = jwt.verify(authCookie, JWT_SECRET) as JwtPayload;
        discovery_url = authContext['url'];
        client_id = authContext['cid'];
    } catch (e) {
        console.error('failed to validate JWT', (e as Error).message);
        return res.status(400).send('Your session has most likely expired.');
    }

    try {
        const client = await getClient(discovery_url, client_id);

        // Exchange code for tokens
        const REDIRECT_URI = getRedirectUri(req);
        const tokenSet = await client.callback(REDIRECT_URI, req.query, { code_verifier: codeVerifier, state: req.sessionID });

        // Fetch user info
        const userinfo = await client.userinfo(tokenSet.access_token as string);
        req.session.userinfo = userinfo as User;

        // STEP 4: We redirect the user back to the page they were trying to access
        return res.redirect(getRedirectUri(req, PORT, redirectPath));
    } catch (err) {
        console.error(err);
        return res.status(500).send('Callback Error');
    }
});

app.listen(PORT, () => {
    console.log(`Auth server listening on http://localhost:${PORT}`);
});
