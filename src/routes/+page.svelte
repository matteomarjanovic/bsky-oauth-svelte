<script>
    import { onMount } from "svelte";
    import {
        authSession,
        startOAuthFlow,
        getRandomFollowedAccounts,
        logout,
    } from "$lib/bskyAuth";

    let isLoading = false;
    let followedAccounts = [];
    let errorMessage = "";

    // Function to handle login button click
    async function handleLogin() {
        isLoading = true;
        try {
            // Start the OAuth flow with Bluesky
            await startOAuthFlow();
            // Note: The page will redirect to Bluesky for authentication
            // and then return to our callback page
        } catch (error) {
            console.error("Authentication error:", error);
            errorMessage =
                error instanceof Error
                    ? error.message
                    : "Failed to authenticate";
            isLoading = false;
        }
    }

    // Function to handle logout
    function handleLogout() {
        logout();
        followedAccounts = [];
    }

    // When the component mounts, check if we're authenticated
    // and fetch followed accounts if we are
    onMount(async () => {
        try {
            // Check if we have a stored session
            const storedSession = localStorage.getItem("bsky:session");
            if (storedSession) {
                const session = JSON.parse(storedSession);

                // Update our auth session
                authSession.isAuthenticated = session.isAuthenticated;
                authSession.accessToken = session.accessToken;
                authSession.refreshToken = session.refreshToken;
                authSession.sub = session.sub;

                // If authenticated, fetch followed accounts
                if (authSession.isAuthenticated && authSession.accessToken) {
                    isLoading = true;
                    try {
                        // We need to regenerate a DPoP keypair since we can't store it
                        // This is a simplified approach for the demo
                        // In a real app, you'd handle token refresh and DPoP key management
                        // more securely

                        // Fetch 3 random followed accounts
                        followedAccounts = await getRandomFollowedAccounts(3);
                    } catch (error) {
                        console.error("Error fetching accounts:", error);
                        errorMessage = "Failed to load followed accounts";
                        // If we get an auth error, clear the session
                        if (
                            error.message.includes("authentication") ||
                            error.message.includes("auth")
                        ) {
                            handleLogout();
                        }
                    } finally {
                        isLoading = false;
                    }
                }
            }
        } catch (error) {
            console.error("Session restoration error:", error);
        } finally {
            isLoading = false;
        }
    });
</script>

<main>
    <header>
        <h1>Bluesky OAuth Example</h1>
    </header>

    <section class="auth-section">
        {#if !authSession.isAuthenticated}
            <button
                on:click={handleLogin}
                disabled={isLoading}
                class="login-button"
            >
                {isLoading ? "Connecting..." : "Login with Bluesky"}
            </button>
        {:else}
            <div class="authenticated">
                <h2>You're logged in!</h2>
                <p>DID: {authSession.sub || "Unknown"}</p>
                <button on:click={handleLogout} class="logout-button"
                    >Logout</button
                >
            </div>
        {/if}
    </section>

    {#if errorMessage}
        <div class="error-message">
            <p>{errorMessage}</p>
        </div>
    {/if}

    {#if authSession.isAuthenticated}
        <section class="followed-accounts">
            <h2>3 Random Accounts You Follow</h2>
            {#if isLoading}
                <div class="loading-accounts">
                    <div class="spinner"></div>
                    <p>Loading accounts...</p>
                </div>
            {:else if followedAccounts.length > 0}
                <div class="accounts-grid">
                    {#each followedAccounts as account}
                        <div class="account-card">
                            <img
                                src={account.avatar ||
                                    "https://bsky.social/static/default-avatar.png"}
                                alt={account.displayName || account.handle}
                            />
                            <h3>{account.displayName || account.handle}</h3>
                            <p>@{account.handle}</p>
                        </div>
                    {/each}
                </div>
            {:else}
                <p>No followed accounts found.</p>
            {/if}
        </section>
    {/if}

    <footer>
        <div class="footer-content">
            <h3>How OAuth Works with Bluesky (AT Protocol)</h3>
            <ol>
                <li>
                    <strong>PKCE Setup:</strong> We generate a code verifier and
                    code challenge to secure the auth flow.
                </li>
                <li>
                    <strong>DPoP Keypair:</strong> We create a unique keypair that
                    binds the access token to this specific client.
                </li>
                <li>
                    <strong>Authorization Request:</strong> Redirect to Bluesky with
                    our client ID and PKCE challenge.
                </li>
                <li>
                    <strong>User Authentication:</strong> User logs in on Bluesky
                    and grants our app permissions.
                </li>
                <li>
                    <strong>Callback:</strong> Bluesky redirects back to our callback
                    page with an authorization code.
                </li>
                <li>
                    <strong>Token Exchange:</strong> We exchange the code for access
                    and refresh tokens.
                </li>
                <li>
                    <strong>API Access:</strong> We use the tokens with DPoP to make
                    authenticated API requests.
                </li>
            </ol>
        </div>
    </footer>
</main>

<style>
    main {
        max-width: 800px;
        margin: 0 auto;
        padding: 2rem;
        font-family:
            system-ui,
            -apple-system,
            sans-serif;
    }

    header {
        margin-bottom: 2rem;
        text-align: center;
    }

    .auth-section {
        display: flex;
        justify-content: center;
        margin-bottom: 2rem;
    }

    .login-button {
        background-color: #0085ff;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 0.75rem 1.5rem;
        font-size: 1rem;
        font-weight: bold;
        cursor: pointer;
        transition: background-color 0.2s;
    }

    .login-button:hover {
        background-color: #0069cc;
    }

    .login-button:disabled {
        background-color: #cccccc;
        cursor: not-allowed;
    }

    .logout-button {
        background-color: #ff4d4f;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 0.5rem 1rem;
        font-size: 0.9rem;
        cursor: pointer;
    }

    .authenticated {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0.5rem;
    }

    .authenticated h2 {
        margin-bottom: 0;
    }

    .authenticated p {
        margin: 0;
        font-family: monospace;
        font-size: 0.9rem;
        color: #666;
    }

    .error-message {
        background-color: #f8d7da;
        color: #721c24;
        padding: 0.75rem;
        border-radius: 4px;
        margin-bottom: 1rem;
        text-align: center;
    }

    .followed-accounts {
        margin-top: 2rem;
    }

    .loading-accounts {
        display: flex;
        flex-direction: column;
        align-items: center;
        margin: 2rem 0;
    }

    .spinner {
        border: 4px solid rgba(0, 0, 0, 0.1);
        border-top: 4px solid #0085ff;
        border-radius: 50%;
        width: 30px;
        height: 30px;
        animation: spin 1s linear infinite;
        margin-bottom: 1rem;
    }

    @keyframes spin {
        0% {
            transform: rotate(0deg);
        }
        100% {
            transform: rotate(360deg);
        }
    }

    .accounts-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
        gap: 1.5rem;
        margin-top: 1rem;
    }

    .account-card {
        border: 1px solid #eaeaea;
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
        transition:
            transform 0.2s,
            box-shadow 0.2s;
    }

    .account-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
    }

    .account-card img {
        width: 80px;
        height: 80px;
        border-radius: 50%;
        object-fit: cover;
        margin-bottom: 0.5rem;
    }

    .account-card h3 {
        margin: 0;
        font-size: 1.1rem;
    }

    .account-card p {
        margin: 0.5rem 0 0;
        color: #666;
        font-size: 0.9rem;
    }

    footer {
        margin-top: 3rem;
        padding-top: 1.5rem;
        border-top: 1px solid #eaeaea;
    }

    .footer-content {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 1.5rem;
    }

    .footer-content h3 {
        margin-top: 0;
    }

    ol {
        padding-left: 1.2rem;
    }

    ol li {
        margin-bottom: 0.5rem;
    }
</style>
