import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import { BaseClient, Issuer, generators } from 'openid-client';
import jwt, { JwtPayload } from 'jsonwebtoken';
import crypto from 'crypto';
import { getCookies } from './Cookies';
import { User } from './User';
import { createPendingAuthSessionToken, createUserAuthSessionToken, verifyAuthSessionToken } from './AuthSession';


const app = express();
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = +(process.env.PORT || 3600);
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const REDIRECT_PATH = process.env.REDIRECT_PATH || '/auth/oidc/callback';
const SESSION_DURATION = +(process.env.SESSION_DURATION || 3600);                         // Duration of the logged-in session
const COOKIE_AUTH_SESSION = process.env.COOKIE_AUTH_SESSION || 'oidc.session';          // Name of the session cookie
const COOKIE_REDIRECT = process.env.COOKIE_REDIRECT || 'oidc.redirect';                 // Name of the redirect cookie

app.use(express.urlencoded({ extended: true }));

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

const NGINX_HEADER_OIDC_CLIENT_ID = 'x-oidc-client-id';
const NGINX_HEADER_OIDC_DISCOVERY_URL = 'x-oidc-discovery-url';
const NGINX_HEADER_OIDC_AUTH_SESSION = 'x-oidc-auth-session';

// STEP 1: NGINX asks if we are authenticated with the specific discovery
app.get('/verify', async (req, res) => {
    // If we have X-OIDC headers, we are coming from a auth_request
    const client_id = req.headers[NGINX_HEADER_OIDC_CLIENT_ID] as string;
    const discovery_url = req.headers[NGINX_HEADER_OIDC_DISCOVERY_URL] as string;
    if (!client_id || !discovery_url) {
        console.error('Missing client_id or discovery_url', { client_id, discovery_url });
        return res.status(500).send('Missing auth_request headers');
    }

    // Check if we have the auth-session already either via a header or otherwise.
    // NGINX Can give us the cookies, but we are not allowed to set cookies.
    // We will need to verify the cookie is correct
    const existingAuthToken = req.headers[NGINX_HEADER_OIDC_AUTH_SESSION] ?? getCookies(req)[COOKIE_AUTH_SESSION];
    if (existingAuthToken) {
        const token = Array.isArray(existingAuthToken) ? existingAuthToken[0] : existingAuthToken;
        const authSession = verifyAuthSessionToken(token, JWT_SECRET);
        if (authSession && 'sub' in authSession)
            return res.status(200).send('Authorized');
        console.warn('User tried to login with a invalid session token.');
    }

    // Store our internal state in a signed JWT. 
    // We will pass this as a header which NGINX can use later.
    const authToken = createPendingAuthSessionToken(client_id, discovery_url, JWT_SECRET);
    res.setHeader(NGINX_HEADER_OIDC_AUTH_SESSION, authToken);
    res.clearCookie(COOKIE_AUTH_SESSION);
    console.log('Unauthorised, telling NGINX');
    return res.status(401).send('Unauthorized');
});

app.get('/login', async (req, res) => {
    // Get the token
    const cookies = getCookies(req);
    const authToken = cookies[COOKIE_AUTH_SESSION];
    if (!authToken) {
        console.error('User attempted to go to /login without the authorization cookie.');
        if (NODE_ENV !== 'production')
            return res.status(500).send('Your state has not been setup with /verify yet. Please try again.');
        return res.redirect(getRedirectUri(req));
    }

    // Validate the token
    const authSession = verifyAuthSessionToken(authToken, JWT_SECRET);
    if (!authSession) {
        console.error('Failed to validate the auth session.');
        res.clearCookie(COOKIE_AUTH_SESSION);   // The cookie is bad, we need to clear it.
        if (NODE_ENV !== 'production')
            return res.status(500).send('Your state was not valid. It is likely expired.');
        return res.redirect(getRedirectUri(req));
    }

    const discoveryUrl = authSession.url;
    const clientId = authSession.cid;
    const state = authSession.state;

    // Normally we would check if we are already logged in, but the user
    // clearly just wants to login again so go ahead.

    // TODO: Check if the clientId is allowed

    const client = await getClient(discoveryUrl, clientId);
    const authorizationUrl = client.authorizationUrl({
        scope: 'openid profile email',
        response_type: 'code',
        redirect_uri: getRedirectUri(req),
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: state,
    });

    console.log('Redirecting user to ', authorizationUrl);
    return res.redirect(authorizationUrl);
});

// STEP 3: OIDC will call back wiht our deets
app.get('/callback', async (req, res) => {
    // Prepare the cookies
    console.log('Recieved a callback, validating the request.');
    const cookies = getCookies(req);
    const redirectPath = cookies[COOKIE_REDIRECT] ?? '';
    res.clearCookie(COOKIE_REDIRECT);

    const authToken = cookies[COOKIE_AUTH_SESSION];
    if (!authToken) {
        console.error('User is on /callback but they do not have an authToken.');
        if (NODE_ENV !== 'production')
            return res.status(500).send('Missing your auth session.');        
        return res.redirect(getRedirectUri(req));
    }

    // Validate the token.
    const authSession = verifyAuthSessionToken(authToken, JWT_SECRET);
    if (!authSession) {
        console.error('Failed to validate the auth session.');
        res.clearCookie(COOKIE_AUTH_SESSION);   // The cookie is bad, we need to clear it.
        if (NODE_ENV !== 'production')
            return res.status(500).send('Your state was not valid. It is likely expired.');
        return res.redirect(getRedirectUri(req));
    }

    const discoveryUrl = authSession.url;
    const clientId = authSession.cid;
    const state = authSession.state;

    try {
        // Exchange code for tokens
        const client = await getClient(discoveryUrl, clientId);
        const redirectUri = getRedirectUri(req);
        const tokenSet = await client.callback(redirectUri, req.query, { code_verifier: codeVerifier, state: state });

        // Fetch user info
        const user = await client.userinfo(tokenSet.access_token as string) as User;

        // Update the user authentication and take them back to where they were
        const userAuthSession = createUserAuthSessionToken(authSession, user, JWT_SECRET, SESSION_DURATION);
        res.cookie(COOKIE_AUTH_SESSION, userAuthSession, {
            httpOnly: true,
            maxAge: SESSION_DURATION * 1000,
            sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
            path: '/'
        });

        console.log('- User has logged in. Welcome', user.name);
        return res.redirect(getRedirectUri(req, PORT, redirectPath));
    } catch (err) {
        console.error('- Failed:', err);
        return res.status(500).send('Callback Error');
    }
});

app.get('/logout', (req, res) => {
    console.log('Someone requested a logout.');
    res.clearCookie(COOKIE_AUTH_SESSION);
    return res.status(200).send('Logged out.');
});

app.listen(PORT, () => {
    console.log(`Auth server listening on http://localhost:${PORT}/`);
});
