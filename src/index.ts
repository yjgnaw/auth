/**********************************************************************
Auth: A very out-of-the-box cloud authentication app powered by cloudflare workers.
Copyright (C) 2026 AlfredChester

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
**********************************************************************/


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
				return new Response('Invalid url path', { status: 404 });
			}
		} catch (e) {
			console.warn('Error processing request:', e);
			return new Response('Internal Server Error', { status: 500 });
		}
	},
} satisfies ExportedHandler<Env>;
