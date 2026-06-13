<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/logo-dark.png">
    <img alt="Authio" src=".github/logo-light.png" width="220">
  </picture>
</p>

# @useauthio/svelte

> Part of **[Authio Lobby](https://authio.com/products/lobby)** —
> Authio's drop-in passwordless authentication. Learn more at
> https://authio.com/products/lobby.

Authio SvelteKit SDK. Server-side JWT verification + Svelte stores for
multi-org auth. Pairs with `@useauthio/node` for JWKS verification on the server.

## Install

```bash
pnpm add @useauthio/svelte @useauthio/node
```

## SvelteKit server hook

```ts
// src/hooks.server.ts
import type { Handle } from "@sveltejs/kit";
import { verifySessionCookie } from "@useauthio/svelte/server";

export const handle: Handle = async ({ event, resolve }) => {
  const token = event.cookies.get("authio_session");
  event.locals.session = await verifySessionCookie(token, {
    apiUrl: process.env.PUBLIC_AUTHIO_API_URL,
  });
  return resolve(event);
};
```

## Client store

```svelte
<script lang="ts">
  import { authio, signIn } from "@useauthio/svelte";

  let email = "";
  async function submit() {
    await signIn({
      email,
      projectId: import.meta.env.PUBLIC_AUTHIO_PROJECT_ID,
      redirectUri: `${location.origin}/api/auth/callback`,
    });
  }
</script>

{#if $authio.session}
  <p>Signed in as {$authio.session.userId}</p>
{:else}
  <form on:submit|preventDefault={submit}>
    <input type="email" bind:value={email} />
    <button>Send magic link</button>
  </form>
{/if}
```

## API

### Browser (`@useauthio/svelte`)

- `authio: Writable<AuthioState>` — default writable store.
- `setSession(session)` — populate the store after the server load.
- `clearSession()` — wipe the store after sign-out.
- `signIn({ email, projectId, redirectUri, apiUrl? })` — POST to
  `/v1/auth/magic-link/send` with the `X-Authio-Project` header and body
  `{ destination, redirect_uri }`.

### Server (`@useauthio/svelte/server`)

- `verifySessionCookie(token, { apiUrl?, issuer?, audience? })` — verify a
  JWT against the cached JWKS. Returns the typed `Session` or `null`.
  Cache-safe to call on every request.

## License

MIT
