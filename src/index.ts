/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import { checkHandler } from "./handlers/check";
import { adminHandler } from "./handlers/admin";

export default {
	async fetch(request, env, ctx): Promise<Response> {
		try {
			const url = new URL(request.url);
			const path = url.pathname.substring(1);
			if (path === 'admin') {
				return await adminHandler(request, env);
			} else if (path === 'check') {
				return await checkHandler(request, env);
			} else {
				throw new Error('Password check failed');
			}
		} catch (e) {
			return new Response('Access denied', { status: 403 });
		}
	},
} satisfies ExportedHandler<Env>;
