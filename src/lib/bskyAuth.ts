import { browser } from '$app/environment';
import * as jose from 'jose';
import { Agent, AtpAgent } from '@atproto/api';

// Types for our auth state
interface AuthSession {
    isAuthenticated: boolean;
    accessToken?: string;
    refreshToken?: string;
    dpopKey?: CryptoKeyPair;
    codeVerifier?: string;
    sub?: string; // The DID of the authenticated user
    serverNonce?: string;
}

// Initial auth state
export const authSession: AuthSession = {
    isAuthenticated: false
};

// Generate a random string for PKCE code verifier
export function generateCodeVerifier(length: number = 128): string {
    if (!browser) return '';

    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let result = '';
    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);

    for (let i = 0; i < length; i++) {
        result += charset[randomValues[i] % charset.length];
    }

    return result;
}

// Generate code challenge from code verifier (for PKCE)
export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
    if (!browser) return '';

    // Convert string to ArrayBuffer
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);

    // Hash the code verifier with SHA-256
    const hash = await crypto.subtle.digest('SHA-256', data);

    // Convert to base64url encoding
    return base64UrlEncode(hash);
}

// Base64Url encoding helper
function base64UrlEncode(buffer: ArrayBuffer): string {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// Generate a DPoP keypair using WebCrypto
export async function generateDpopKeypair(): Promise<CryptoKeyPair> {
    if (!browser) {
        throw new Error('This function can only be run in the browser');
    }

    return await crypto.subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-256' // ES256 required by Bluesky
        },
        true, // Make keys extractable so we can export them for jose
        ['sign', 'verify'] // can be used for signing and verification
    );
}

// Create a DPoP JWT for token requests using the jose library
export async function createDpopJwt(
    keypair: CryptoKeyPair,
    method: string,
    url: string,
    nonce?: string,
    accessToken?: string
): Promise<string> {
    if (!browser) return '';

    try {
        // Extract the public key to JWK format for inclusion in the header
        const publicKeyJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);

        // Create the payload
        const payload: any = {
            jti: crypto.randomUUID(),
            htm: method,
            htu: url,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 120 // 2 minutes expiration
        };

        // Add optional fields
        if (nonce) {
            payload.nonce = nonce;
        }

        if (accessToken) {
            // Hash the access token and add it to the payload
            const encoder = new TextEncoder();
            const data = encoder.encode(accessToken);
            const hash = await crypto.subtle.digest('SHA-256', data);
            payload.ath = base64UrlEncode(hash);
        }

        // Use jose to create a properly formatted JWT
        // Note that we need to convert our WebCrypto keypair to a format jose can use
        const privateKey = await jose.importJWK(
            await crypto.subtle.exportKey('jwk', keypair.privateKey),
            'ES256'
        );

        // Create a signed JWT with the jose library
        const dpopJwt = await new jose.SignJWT(payload)
            .setProtectedHeader({
                alg: 'ES256',
                typ: 'dpop+jwt',
                jwk: {
                    kty: publicKeyJwk.kty,
                    crv: publicKeyJwk.crv,
                    x: publicKeyJwk.x,
                    y: publicKeyJwk.y
                }
            })
            .sign(privateKey);

        console.log('Created DPoP JWT with jose library');
        return dpopJwt;
    } catch (error) {
        console.error('Error creating DPoP JWT:', error);
        throw error;
    }
}

// Initialize the OAuth flow by redirecting to the authorization server
export async function startOAuthFlow(serverUrl: string = 'https://bsky.social'): Promise<void> {
    if (!browser) return;

    try {
        // 1. Generate and store PKCE code verifier
        const codeVerifier = generateCodeVerifier();
        localStorage.setItem('bsky:codeVerifier', codeVerifier);

        // 2. Generate code challenge
        const codeChallenge = await generateCodeChallenge(codeVerifier);

        // 3. Generate state parameter (anti-CSRF)
        const state = crypto.randomUUID();
        localStorage.setItem('bsky:state', state);

        // 4. Store the authorization server URL
        localStorage.setItem('bsky:serverUrl', serverUrl);

        // 5. Construct the authorization URL
        const clientId = 'https://bsky-oauth-svelte.netlify.app/client-metadata.json';
        const redirectUri = `${window.location.origin}/callback`;

        const authUrl = new URL(`${serverUrl}/oauth/authorize`);
        authUrl.searchParams.append('client_id', clientId);
        authUrl.searchParams.append('response_type', 'code');
        authUrl.searchParams.append('redirect_uri', redirectUri);
        authUrl.searchParams.append('scope', 'atproto');
        authUrl.searchParams.append('state', state);
        authUrl.searchParams.append('code_challenge', codeChallenge);
        authUrl.searchParams.append('code_challenge_method', 'S256');

        // 6. Redirect the user to the authorization server
        window.location.href = authUrl.toString();

    } catch (error) {
        console.error('Failed to start OAuth flow:', error);
        throw error;
    }
}

// Handle the OAuth callback and exchange code for tokens
export async function handleOAuthCallback(queryParams: URLSearchParams): Promise<AuthSession> {
    if (!browser) return authSession;

    try {
        // 1. Verify state parameter to prevent CSRF
        const storedState = localStorage.getItem('bsky:state');
        const returnedState = queryParams.get('state');

        if (!storedState || storedState !== returnedState) {
            throw new Error('Invalid state parameter');
        }

        // 2. Get the authorization code
        const code = queryParams.get('code');
        if (!code) {
            throw new Error('No authorization code returned');
        }

        // 3. Get the code verifier from storage
        const codeVerifier = localStorage.getItem('bsky:codeVerifier');
        if (!codeVerifier) {
            throw new Error('No code verifier found');
        }

        // 4. Get the server URL
        const serverUrl = localStorage.getItem('bsky:serverUrl') || 'https://bsky.social';

        // 5. Generate a new DPoP keypair
        const dpopKeypair = await generateDpopKeypair();

        // 6. First, make a valid request to get a DPoP nonce, using actual parameters
        let dpopNonce = '';
        try {
            console.log('Making initial request to get DPoP nonce...');

            // Create a proper token request (with our client_id) to get a nonce
            const clientId = 'https://bsky-oauth-svelte.netlify.app/client-metadata.json';

            // First create a DPoP JWT without a nonce
            const initialDpopJwt = await createDpopJwt(
                dpopKeypair,
                'POST',
                `${serverUrl}/oauth/token`
            );

            // Generate a dummy code verifier of appropriate length (at least 43 chars)
            const dummyCodeVerifier = generateCodeVerifier(64);

            // Make a proper request that will fail but return a nonce
            const initialResponse = await fetch(`${serverUrl}/oauth/token`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'DPoP': initialDpopJwt
                },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    code: 'dummy-code', // This will fail but should return a nonce
                    redirect_uri: `${window.location.origin}/callback`,
                    client_id: clientId,
                    code_verifier: dummyCodeVerifier // Using a properly formatted code verifier
                }).toString()
            });

            // Extract the DPoP-Nonce header
            dpopNonce = initialResponse.headers.get('DPoP-Nonce') || '';
            console.log('Got DPoP nonce:', dpopNonce);

            // Log the error response (for debugging)
            try {
                const errorData = await initialResponse.json();
                console.log('Expected error when requesting nonce:', errorData);
            } catch (e) {
                // Ignore parsing errors
            }
        } catch (error) {
            console.error('Failed to get DPoP nonce:', error);
        }

        if (!dpopNonce) {
            console.warn('No DPoP nonce received, proceeding without it');
        }

        // 7. Create a DPoP JWT for the token request with the nonce
        const tokenEndpoint = `${serverUrl}/oauth/token`;
        const dpopJwt = await createDpopJwt(
            dpopKeypair,
            'POST',
            tokenEndpoint,
            dpopNonce
        );

        console.log('Created DPoP JWT for token request');

        // 8. Exchange the code for tokens
        const tokenRequestBody = new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: `${window.location.origin}/callback`,
            client_id: 'https://bsky-oauth-svelte.netlify.app/client-metadata.json',
            code_verifier: codeVerifier
        });

        console.log('Making token request with params:', Object.fromEntries(tokenRequestBody));

        const tokenResponse = await fetch(tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'DPoP': dpopJwt
            },
            body: tokenRequestBody
        });

        console.log('Token response status:', tokenResponse.status);

        // If we received a DPoP-Nonce in the response, save it
        const newNonce = tokenResponse.headers.get('DPoP-Nonce');
        if (newNonce) {
            console.log('Got new DPoP nonce in token response:', newNonce);
            authSession.serverNonce = newNonce;
        }

        if (!tokenResponse.ok) {
            let errorMsg = 'Token request failed';
            try {
                const errorData = await tokenResponse.json();
                errorMsg += `: ${errorData.error}`;
                if (errorData.error_description) {
                    errorMsg += ` - ${errorData.error_description}`;
                }
                console.error('Token error details:', errorData);

                // Handle the case where we need to use a DPoP nonce
                if (errorData.error === 'use_dpop_nonce' && newNonce) {
                    console.log('Retrying with new DPoP nonce');
                    // Attempt to retry with the new nonce
                    const retryDpopJwt = await createDpopJwt(
                        dpopKeypair,
                        'POST',
                        tokenEndpoint,
                        newNonce
                    );

                    const retryResponse = await fetch(tokenEndpoint, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'DPoP': retryDpopJwt
                        },
                        body: tokenRequestBody
                    });

                    if (retryResponse.ok) {
                        const tokenData = await retryResponse.json();
                        authSession.isAuthenticated = true;
                        authSession.accessToken = tokenData.access_token;
                        authSession.refreshToken = tokenData.refresh_token;
                        authSession.dpopKey = dpopKeypair;
                        authSession.codeVerifier = codeVerifier;
                        authSession.sub = tokenData.sub;
                        authSession.serverNonce = retryResponse.headers.get('DPoP-Nonce') || newNonce;

                        localStorage.setItem('bsky:session', JSON.stringify({
                            isAuthenticated: true,
                            accessToken: tokenData.access_token,
                            refreshToken: tokenData.refresh_token,
                            sub: tokenData.sub,
                            serverNonce: authSession.serverNonce
                        }));

                        return authSession;
                    } else {
                        const retryErrorData = await retryResponse.json();
                        throw new Error(`Retry token request failed: ${retryErrorData.error}`);
                    }
                }
            } catch (e) {
                console.error('Failed to parse error response', e);
            }
            throw new Error(errorMsg);
        }

        // 9. Parse the token response
        const tokenData = await tokenResponse.json();
        console.log('Received token data:', {
            access_token: tokenData.access_token ? '✓' : '✗',
            refresh_token: tokenData.refresh_token ? '✓' : '✗',
            sub: tokenData.sub || 'missing'
        });

        // 10. Update and return the auth session
        authSession.isAuthenticated = true;
        authSession.accessToken = tokenData.access_token;
        authSession.refreshToken = tokenData.refresh_token;
        authSession.dpopKey = dpopKeypair;
        authSession.codeVerifier = codeVerifier;
        authSession.sub = tokenData.sub; // DID of the authenticated user

        // Store auth session in localStorage (in real app, use more secure storage)
        localStorage.setItem('bsky:session', JSON.stringify({
            isAuthenticated: true,
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token,
            sub: tokenData.sub,
            serverNonce: authSession.serverNonce
        }));

        return authSession;

    } catch (error) {
        console.error('OAuth callback error:', error);
        throw error;
    }
}

// Get three random accounts the user follows using the official API client
export async function getRandomFollowedAccounts(count = 3): Promise<any[]> {
    if (!browser || !authSession.isAuthenticated || !authSession.accessToken) {
        throw new Error('Not authenticated');
    }

    try {
        const serverUrl = localStorage.getItem('bsky:serverUrl') || 'https://bsky.social';

        // Create a session object that can be used by the Agent
        const session = {
            accessJwt: authSession.accessToken,
            refreshJwt: authSession.refreshToken || '',
            did: authSession.sub || '',
            handle: '', // This will be populated by the API

            // Agent requires these methods
            fetch: async (url: string, init?: RequestInit) => {
                return fetch(url, init);
            },

            refreshSession: async () => {
                // This would normally refresh the session, but for this simple example
                // we'll just return the current session
                return session;
            },

            signOut: async () => {
                // Clean up session data
                logout();
            }
        };

        // Create an Agent instance with our session
        const agent = new Agent(session);

        // Get the follows using the agent
        const response = await agent.getFollows({
            actor: authSession.sub || '',
            limit: 100
        });

        if (!response.success) {
            throw new Error('Failed to get follows data');
        }

        const follows = response.data.follows || [];

        // Randomly select the requested number of accounts
        const randomFollows = [];
        if (follows.length <= count) {
            return follows;
        }

        // Create a copy of the follows array to randomly select from
        const followsCopy = [...follows];
        for (let i = 0; i < count && followsCopy.length > 0; i++) {
            const randomIndex = Math.floor(Math.random() * followsCopy.length);
            randomFollows.push(followsCopy[randomIndex]);
            followsCopy.splice(randomIndex, 1);
        }

        return randomFollows.map(follow => ({
            did: follow.did,
            handle: follow.handle,
            displayName: follow.displayName,
            avatar: follow.avatar
        }));

    } catch (error) {
        console.error('Failed to get followed accounts:', error);
        throw error;
    }
}

// Logout function
export function logout(): void {
    if (!browser) return;

    // Clear auth session
    authSession.isAuthenticated = false;
    authSession.accessToken = undefined;
    authSession.refreshToken = undefined;
    authSession.dpopKey = undefined;
    authSession.codeVerifier = undefined;
    authSession.sub = undefined;
    authSession.serverNonce = undefined;

    // Clear storage
    localStorage.removeItem('bsky:session');
    localStorage.removeItem('bsky:codeVerifier');
    localStorage.removeItem('bsky:state');
    localStorage.removeItem('bsky:serverUrl');
}