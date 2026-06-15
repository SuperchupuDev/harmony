import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { styleText } from 'node:util';
import { serve } from '@hono/node-server';
import {
  type APIUser,
  CDNRoutes,
  ImageFormat,
  OAuth2Routes,
  type RESTPostOAuth2AccessTokenResult,
  RouteBases,
  Routes
} from 'discord-api-types/v10';
import { Hono } from 'hono';
import { deleteCookie, setCookie } from 'hono/cookie';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { trimTrailingSlash } from 'hono/trailing-slash';
import say from 'say';
import { decrypt, encrypt, generateIv } from './crypto.ts';
import { database } from './database.ts';
import { env } from './env.ts';
import type { User } from './types.ts';

const port = 5073;

console.log(
  styleText('magenta', ` /_ _  __ _  _  _    \n/ //_|// / //_// //_/  ${env.BASE_URL.origin}\n                  _/`)
);

const app = new Hono();

app.use(logger());
app.use(trimTrailingSlash());

if (env.BASE_URL.hostname !== 'localhost') {
  const parts = env.BASE_URL.hostname.split('.');
  const { origin } = env.BASE_URL;
  app.use(
    '*',
    cors({
      origin: parts.length === 2 ? origin : `${env.BASE_URL.protocol}//${origin.slice(origin.indexOf('.') + 1)}`
    })
  );
}

app.get('/auth/discord', c => {
  const params = new URLSearchParams({
    client_id: env.CLIENT_ID,
    response_type: 'code',
    redirect_uri: `${env.BASE_URL}auth/discord/callback`,
    scope: 'identify',
    prompt: 'none'
  });

  return c.redirect(`${OAuth2Routes.authorizationURL}?${params}`);
});

app.get('/', async c => {
  // prototype client
  const html = await readFile(path.join(import.meta.dirname, './index.html'), 'utf-8');
  return c.html(html);
});

app.get('/users/@me', async c => {
  const authToken = c.req.header('Authorization');

  if (!authToken) {
    c.status(403);
    return c.text('Missing "Authorization" header');
  }

  const tokenBytes = Uint8Array.fromBase64(authToken);
  const userAuth = database
    .prepare(`
      SELECT access_token_iv, banned
        FROM users
        WHERE access_token = ?
  `)
    .get(tokenBytes) as User | undefined;

  if (!userAuth?.access_token_iv) {
    c.status(403);
    return c.text('Session not found');
  }

  const accessToken = await decrypt(tokenBytes, userAuth.access_token_iv);

  const response = await fetch(`${RouteBases.api}/${Routes.user()}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });

  if (!response.ok) {
    c.status(400);
    return c.text(`Discord user endpoint returned ${response.status} ${response.statusText}`);
  }

  const user = (await response.json()) as APIUser;

  database
    .prepare(`
      UPDATE users
        SET username = @username, avatar = @avatar
        WHERE id = @id
    `)
    .run({
      id: user.id,
      username: user.username,
      avatar: user.avatar
    });

  const avatarURL = user.avatar
    ? CDNRoutes.userAvatar(user.id, user.avatar, user.avatar.startsWith('a_') ? ImageFormat.GIF : ImageFormat.WebP)
    : CDNRoutes.defaultUserAvatar((Number(BigInt(user.id) >> 22n) % 6) as 0);

  return c.json({
    id: user.id,
    username: user.username,
    avatar: avatarURL,
    banned: userAuth.banned ?? false
  });
});

app.get('/users/:id', c => {
  const userId = c.req.param('id');

  if (!userId) {
    c.status(400);
    return c.text('Missing user id');
  }

  const user = database
    .prepare(`
      SELECT username, avatar, banned
        FROM users
        WHERE id = ?
  `)
    .get(userId) as User | undefined;

  if (!user) {
    c.status(404);
    return c.text('User not found');
  }

  const avatarURL = user.avatar
    ? CDNRoutes.userAvatar(userId, user.avatar, user.avatar.startsWith('a_') ? ImageFormat.GIF : ImageFormat.WebP)
    : CDNRoutes.defaultUserAvatar((Number(BigInt(user.id) >> 22n) % 6) as 0);

  return c.json({
    id: userId,
    username: user.username,
    avatar: avatarURL,
    banned: user.banned ?? false
  });
});

function handleCookieDomain(hostname: string): string | undefined {
  if (hostname === 'localhost') {
    return undefined;
  }

  const parts = hostname.split('.');

  if (parts.length === 2) {
    return `.${hostname}`;
  }

  return hostname.slice(parts[0].length);
}

interface Gwell {
  name?: string;
  text?: string;
  color?: string;
}

app.get('/gwell', c => {
  const them = database
    .prepare(`
      SELECT name, text, color
        FROM gwell
        WHERE id = 0
    `)
    .get() as Gwell;

  return c.html(`
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="color-scheme" content="light dark" />
      <style>
        main {
          color: ${them.color?.replaceAll(/<>/g, '') ?? 'CanvasText'};
          text-align: center;
          margin-top: 20vh
        }
        button {
          margin-top: 30vh;
        }
      </style>
    </head>
    <body>
      <main>
        <h1>${them.name?.replaceAll(/<>/g, '') ?? 'not set right now'}</h1>
        <p>${them.text?.replaceAll(/<>/g, '') ?? ''}</p>
        <a href="/gwell/admin"><button>admin page</button></a>
      </main>
    </body>
  `);
});

app.get('/gwell/admin', c => {
  return c.html(`<!doctype html>
  <html lang="en">
    <head>
      <meta name="color-scheme" content="light dark" />
      <style>
        main {
          text-align: center;
        }
      </style>
    </head>
    <body>
    <form method="post">
      <label>
        Name:
        <input name="name" required />
      </label>
      <label>
        Additional text:
        <input name="text" />
      </label>
      <label>
        Color:
        <input type="color" name="color" />
      </label>
      <label>
        Password:
        <input type="password" name="password" required />
      </label>
      <button>Save</button>
    </form>
    </body>`);
});

app.post('/gwell/admin', async c => {
  const data = await c.req.formData();
  if (!data) {
    c.status(403);
    return c.text('no password');
  }

  const pass = new TextEncoder().encode((data.get('password') as string) ?? '');
  const hash = await crypto.subtle.digest('SHA-256', pass);
  console.log(new Uint8Array(hash).toHex());

  if (new Uint8Array(hash).toHex() !== env.GWELL_SECRET) {
    c.status(403);
    return c.text('wrøng passwørd :)');
  }

  const color = data.get('color') as string;

  database
    .prepare(`
      UPDATE gwell
        SET name = @name, text = @text, color = @color
        WHERE id = 0
    `)
    .run({
      name: data.get('name') as string,
      text: data.get('text') as string,
      color: color === '#ffffff' || color === '#000000' ? null : color
    });

  return c.redirect('/gwell');
});

app.get('/auth/discord/callback', async c => {
  const code = c.req.query('code');
  const error = c.req.query('error');

  if (error === 'access_denied') {
    return c.redirect('/');
  }

  if (!code) {
    c.status(403);
    return c.text('Missing "code" parameter');
  }

  const response = await fetch(`${RouteBases.api}/${Routes.oauth2TokenExchange()}`, {
    method: 'POST',
    body: new URLSearchParams({
      client_id: env.CLIENT_ID,
      client_secret: env.CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: `${env.BASE_URL}auth/discord/callback`,
      scope: 'identify'
    }).toString(),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });

  if (!response.ok) {
    c.status(400);
    const data = (await response.json()) as { error_description: string };
    return c.text(`Discord token oauth returned ${response.status} (${data.error_description})`);
  }

  const oauthData = (await response.json()) as RESTPostOAuth2AccessTokenResult;
  const expiresAt = Temporal.Now.instant().epochMilliseconds + oauthData.expires_in;

  const userResponse = await fetch(`${RouteBases.api}/${Routes.user()}`, {
    headers: {
      Authorization: `${oauthData.token_type} ${oauthData.access_token}`
    }
  });

  if (!userResponse.ok) {
    c.status(400);
    return c.text(`Discord user endpoint returned ${userResponse.status} ${userResponse.statusText}`);
  }

  const user = (await userResponse.json()) as APIUser;

  const accessTokenIv = generateIv();
  const refreshTokenIv = generateIv();

  const accessToken = await encrypt(oauthData.access_token, accessTokenIv);
  const refreshToken = await encrypt(oauthData.refresh_token, refreshTokenIv);

  database
    .prepare(`
      INSERT INTO users (
        id, username, avatar, access_token, access_token_iv, refresh_token, refresh_token_iv, expires_at
      )
        VALUES (
          @id, @username, @avatar, @accessToken, @accessTokenIv, @refreshToken, @refreshTokenIv, @expiresAt
        )
        ON CONFLICT (id) DO UPDATE
          SET username = @username, avatar = @avatar,
            access_token = @accessToken, access_token_iv = @accessTokenIv,
            refresh_token = @refreshToken, refresh_token_iv = @refreshTokenIv,
            expires_at = @expiresAt
    `)
    .run({
      id: user.id,
      username: user.username,
      avatar: user.avatar,
      accessToken: new DataView(accessToken),
      accessTokenIv,
      refreshToken: new DataView(refreshToken),
      refreshTokenIv,
      expiresAt
    });

  setCookie(c, 'access_token', new Uint8Array(accessToken).toBase64(), {
    domain: handleCookieDomain(env.BASE_URL.hostname),
    secure: true,
    sameSite: 'Lax',
    maxAge: oauthData.expires_in
  });
  return c.redirect('/');
});

app.post('/auth/logout', async c => {
  const authToken = c.req.header('Authorization');

  if (!authToken) {
    c.status(400);
    return c.text('Missing "Authorization" header');
  }

  const tokenBytes = Uint8Array.fromBase64(authToken);
  const user = database
    .prepare(`
      SELECT access_token_iv
        FROM users
        WHERE access_token = ?
  `)
    .get(tokenBytes) as User | undefined;

  if (!user?.access_token_iv) {
    c.status(403);
    return c.text('Session not found');
  }

  const token = await decrypt(tokenBytes, user.access_token_iv);

  const response = await fetch(`${RouteBases.api}/${Routes.oauth2TokenRevocation()}`, {
    method: 'POST',
    body: new URLSearchParams({
      client_id: env.CLIENT_ID,
      client_secret: env.CLIENT_SECRET,
      token,
      token_type_hint: 'access_token'
    }).toString(),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });

  if (!response.ok) {
    c.status(400);
    const data = (await response.json()) as { error_description: string };
    return c.text(`Discord token oauth returned ${response.status} (${data.error_description})`);
  }

  database
    .prepare(`
      UPDATE users
        SET access_token = NULL, access_token_iv = NULL, expires_at = NULL
        WHERE access_token = ?
    `)
    .run(tokenBytes);

  deleteCookie(c, 'access_token');
  return c.text('ok');
});

app.get('/voice', c => {
  const text = c.req.query('text');

  if (!text) {
    c.status(400);
    return c.text('Missing "text" parameter');
  }

  say.speak(text);

  return c.text('ok');
});

serve({ fetch: app.fetch, port });
