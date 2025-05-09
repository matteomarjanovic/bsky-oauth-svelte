import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		allowedHosts: ['514b-2001-999-594-bfc9-cd41-fff8-a868-c7a5.ngrok-free.app'],
	},
});
