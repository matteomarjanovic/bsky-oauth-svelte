<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { handleOAuthCallback } from '$lib/bskyAuth';

  let error = '';
  let isProcessing = true;

  onMount(async () => {
    try {
      // Get the query parameters from the URL
      const queryParams = new URLSearchParams(window.location.search);
      
      // Check for error response from the auth server
      if (queryParams.has('error')) {
        error = queryParams.get('error') || 'Unknown error';
        isProcessing = false;
        return;
      }
      
      // Handle the OAuth callback
      await handleOAuthCallback(queryParams);
      
      // Redirect back to the home page
      goto('/');
    } catch (err) {
      console.error('Error handling callback:', err);
      error = err instanceof Error ? err.message : 'Unknown error occurred';
      isProcessing = false;
    }
  });
</script>

<main>
  <div class="callback-container">
    {#if isProcessing}
      <div class="loading">
        <h2>Processing authentication...</h2>
        <div class="spinner"></div>
      </div>
    {:else if error}
      <div class="error">
        <h2>Authentication Error</h2>
        <p>{error}</p>
        <button on:click={() => goto('/')}>Return to Home</button>
      </div>
    {/if}
  </div>
</main>

<style>
  .callback-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100vh;
    text-align: center;
    padding: 1rem;
  }

  .loading, .error {
    max-width: 600px;
    background-color: white;
    border-radius: 8px;
    padding: 2rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  }

  .spinner {
    border: 4px solid rgba(0, 0, 0, 0.1);
    border-top: 4px solid #0085ff;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    animation: spin 1s linear infinite;
    margin: 1rem auto;
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  .error {
    color: #721c24;
    background-color: #f8d7da;
    border: 1px solid #f5c6cb;
  }

  button {
    background-color: #0085ff;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 0.75rem 1.5rem;
    font-size: 1rem;
    cursor: pointer;
    margin-top: 1rem;
  }

  button:hover {
    background-color: #0069cc;
  }
</style>