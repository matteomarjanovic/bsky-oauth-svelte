import { browser } from '$app/environment';

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
        false, // not extractable
        ['sign', 'verify'] // can be used for signing and verification
    );
}

// Create a DPoP JWT for token requests
export async function createDpopJwt(
    keypair: CryptoKeyPair,
    method: string,
    url: string,
    nonce?: string,
    accessToken?: string
): Promise<string> {
    if (!browser) return '';

    // Extract the public key to JWK format
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);

    // Create header
    const header = {
        typ: 'dpop+jwt',
        alg: 'ES256',
        jwk: publicKeyJwk
    };

    // Create payload
    const payload: any = {
        jti: crypto.randomUUID(),
        htm: method,
        htu: url,
        iat: Math.floor(Date.now() / 1000)
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

    // Encode header and payload
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));

    // Create the signature input
    const signatureInput = `${encodedHeader}.${encodedPayload}`;

    // Sign the token
    const encoder = new TextEncoder();
    const data = encoder.encode(signatureInput);
    const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keypair.privateKey,
        data
    );

    // Encode the signature
    const encodedSignature = base64UrlEncode(signature);

    // Combine to form the complete JWT
    return `${signatureInput}.${encodedSignature}`;
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

        // 3. Generate and store DPoP keypair
        const dpopKeypair = await generateDpopKeypair();
        // We can't store the keypair directly, so we'll handle this in a production app differently
        // This is a simplified example

        // 4. Generate state parameter (anti-CSRF)
        const state = crypto.randomUUID();
        localStorage.setItem('bsky:state', state);

        // 5. Store the authorization server URL
        localStorage.setItem('bsky:serverUrl', serverUrl);

        // 6. Construct the authorization URL
        // In a real implementation, we would make a PAR request first
        // For this example, we'll use a simplified approach
        const clientId = 'https://bsky-oauth-svelte.netlify.app/client-metadata.json'; // This should be your client metadata URL
        const redirectUri = `${window.location.origin}/callback`;

        const authUrl = new URL(`${serverUrl}/oauth/authorize`);
        authUrl.searchParams.append('client_id', clientId);
        authUrl.searchParams.append('response_type', 'code');
        authUrl.searchParams.append('redirect_uri', redirectUri);
        authUrl.searchParams.append('scope', 'atproto');
        authUrl.searchParams.append('state', state);
        authUrl.searchParams.append('code_challenge', codeChallenge);
        authUrl.searchParams.append('code_challenge_method', 'S256');

        // 7. Redirect the user to the authorization server
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

        // 6. First, make a request to get a DPoP nonce
        // This is a crucial step we were missing before
        let dpopNonce = '';
        try {
            const initialRequest = await fetch(`${serverUrl}/oauth/token`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: 'invalid=invalid' // Dummy body to trigger a response
            });

            // Extract the DPoP-Nonce header
            dpopNonce = initialRequest.headers.get('DPoP-Nonce') || '';
            console.log('Got DPoP nonce:', dpopNonce);
        } catch (error) {
            console.error('Failed to get DPoP nonce:', error);
        }

        // 7. Create a DPoP JWT for the token request with the nonce
        const dpopJwt = await createDpopJwt(
            dpopKeypair,
            'POST',
            `${serverUrl}/oauth/token`,
            dpopNonce
        );

        // 8. Exchange the code for tokens
        const tokenResponse = await fetch(`${serverUrl}/oauth/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'DPoP': dpopJwt
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code,
                redirect_uri: `${window.location.origin}/callback`,
                client_id: 'https://bsky-oauth-svelte.netlify.app/client-metadata.json',
                code_verifier: codeVerifier
            })
        });

        // Log response for debugging
        console.log('Token response status:', tokenResponse.status);

        if (!tokenResponse.ok) {
            let errorMsg = 'Token request failed';
            try {
                const errorData = await tokenResponse.json();
                errorMsg += `: ${errorData.error}`;
                console.error('Token error details:', errorData);
            } catch (e) {
                console.error('Failed to parse error response', e);
            }
            throw new Error(errorMsg);
        }

        // 9. Parse the token response
        const tokenData = await tokenResponse.json();

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
            sub: tokenData.sub
            // Note: We can't store the CryptoKey directly in localStorage
        }));

        return authSession;

    } catch (error) {
        console.error('OAuth callback error:', error);
        throw error;
    }
}

// Get three random accounts the user follows
export async function getRandomFollowedAccounts(count = 3): Promise<any[]> {
    if (!browser || !authSession.isAuthenticated || !authSession.accessToken || !authSession.dpopKey) {
        throw new Error('Not authenticated');
    }

    try {
        const serverUrl = localStorage.getItem('bsky:serverUrl') || 'https://bsky.social';
        const apiUrl = `${serverUrl}/xrpc/app.bsky.graph.getFollows`;
        const endpoint = new URL(apiUrl);
        endpoint.searchParams.append('actor', authSession.sub || '');
        endpoint.searchParams.append('limit', '100'); // Get a larger set to select random ones from

        // Create DPoP JWT for the API request
        const dpopJwt = await createDpopJwt(
            authSession.dpopKey,
            'GET',
            endpoint.toString(),
            authSession.serverNonce,
            authSession.accessToken
        );

        // Make the API request
        const response = await fetch(endpoint.toString(), {
            method: 'GET',
            headers: {
                'Authorization': `DPoP ${authSession.accessToken}`,
                'DPoP': dpopJwt
            }
        });

        // If we get a nonce error, we need to update our nonce and retry
        if (response.status === 401) {
            const newNonce = response.headers.get('DPoP-Nonce');
            if (newNonce) {
                authSession.serverNonce = newNonce;
                // Retry with the new nonce
                return getRandomFollowedAccounts(count);
            }
        }

        if (!response.ok) {
            throw new Error(`API request failed: ${response.statusText}`);
        }

        const data = await response.json();
        const follows = data.follows || [];

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