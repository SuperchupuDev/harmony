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
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { logger } from 'hono/logger';
import say from 'say';
import { Temporal } from 'temporal-polyfill-lite';

import { decrypt, encrypt, generateIv } from './crypto.ts';
import { database } from './database.ts';
import { env } from './env.ts';
import type { User } from './types.ts';

console.log(styleText('magenta', ' /_ _  __ _  _  _    \n/ //_|// / //_// //_/\n                  _/ '));

const app = new Hono();

app.use(logger());

app.get('/auth/discord', c => {
  const params = new URLSearchParams({
    client_id: env.CLIENT_ID,
    response_type: 'code',
    redirect_uri: 'http://localhost:3000/auth/discord/callback',
    scope: 'identify',
    prompt: 'none'
  });

  return c.redirect(`${OAuth2Routes.authorizationURL}?${params}`);
});

app.get('/', async c => {
  const tokenCookie = getCookie(c, 'access_token');

  if (!tokenCookie) {
    return c.html(`
    <!doctype html>
    <html>
      <head>
        <meta name="color-scheme" content="light dark" />
      </head>
      <body>
        <p>You haven't logged in yet<p>
        <a href="/auth/discord"><button>log in</button></a>
      </body>
    </html>
  `);
  }

  const tokenBytes = Uint8Array.fromBase64(tokenCookie);
  const user = database
    .prepare(`
      SELECT id, username, avatar, access_token_iv
        FROM users
        WHERE access_token = ?
  `)
    .get(tokenBytes) as User | undefined;

  if (!user?.access_token_iv) {
    c.status(403);
    return c.text('Session not found');
  }

  const accessToken = await decrypt(tokenBytes, user.access_token_iv);
  console.log(accessToken);

  const avatarURL = user.avatar
    ? CDNRoutes.userAvatar(user.id, user.avatar, ImageFormat.WebP)
    : CDNRoutes.defaultUserAvatar((Number(BigInt(user.id) >> 22n) % 6) as 0);

  return c.html(`
    <!doctype html>
    <html>
      <head>
        <meta name="color-scheme" content="light dark" />
      </head>
      <body>
        <h1>${user.username}</h1>
        <p>${user.id}</p>
        <img src="${RouteBases.cdn}/${avatarURL}">
        <p>
          <a href="/auth/logout"><button>log out</button></a>
        </p>
        <input type="text">
        <button type="submit" onclick="console.log(event)">submit</button>
      </body>
    </html>
  `);
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
      redirect_uri: 'http://localhost:3000/auth/discord/callback',
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
    return c.text(`Discord user endpoint returned ${response.status} ${response.statusText}`);
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
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: oauthData.expires_in
  });
  return c.redirect('/');
});

app.get('/auth/logout', async c => {
  const tokenCookie = getCookie(c, 'access_token');

  if (!tokenCookie) {
    c.status(400);
    return c.text('Missing "access_token" cookie');
  }

  const tokenBytes = Uint8Array.fromBase64(tokenCookie);
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
  return c.redirect('/');
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

serve(app);
