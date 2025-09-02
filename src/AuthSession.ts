import jwt, { JwtPayload } from 'jsonwebtoken';
import crypto from 'crypto';
import { User } from './User';

export interface PendingAuthSession {
    /** client id */
    cid: string;
    /** discovery url */
    url: string;

    /** request state */
    state: string;

    /** issued timestamp (in seconds) */
    iat: number;
    /** expire timestamp (in seconds) */
    exp: number;
}

export interface UserAuthSession extends PendingAuthSession {
    /** User that owns the claim */
    sub: string;
    /** Name of the user */
    name: string;
    /** Email of the user */
    email: string;
}

export function createPendingAuthSessionToken(clientId: string, discoveryUrl: string, signSecret: string, duration: number = 60): string {
    const authSession: PendingAuthSession = {
        cid: clientId,
        url: discoveryUrl,
        state: crypto.randomBytes(8).toString('hex'),
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + duration
    };
    return jwt.sign(authSession, signSecret);
}

export function createUserAuthSessionToken(pendingAuthSession: PendingAuthSession, user: User, signSecret: string, duration: number = 8600) {
    const authSession: UserAuthSession = {
        ...pendingAuthSession,
        sub: user.sub,
        name: user.name,
        email: user.email,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + duration
    };
    return jwt.sign(authSession, signSecret);
}


export function verifyAuthSessionToken(token: string, signSecret: string): PendingAuthSession | UserAuthSession | undefined {
    try {
        // Validate the token and the minimum set of claims
        const claims = jwt.verify(token, signSecret) as Object;
        
        // Validate Pending Auth Session
        if ('cid' in claims && 'url' in claims && 'iat' in claims && 'exp' in claims && 'state' in claims) {
            const pendingAuthSession = claims as PendingAuthSession;
            return pendingAuthSession;
        }

        throw new Error('Claims does not have the required CID, URL, IAT, EXP, and STATE');
    } catch (e) {
        console.error('Invalid JWT token provided:', (e as Error).message);
        return undefined;
    }
}