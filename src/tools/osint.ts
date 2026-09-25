// =============================================================================
// OSINT ENGINE — public-source people lookup, username sweeps, breach exposure
// =============================================================================
// Every lookup here rides PUBLIC, keyless sources (site profile probes, Gravatar,
// XposedOrNot, LeakCheck public, HIBP catalog + Pwned Passwords k-anonymity).
// The deep "dump lane" (LeakCheck v2 / DeHashed / Snusbase / IntelligenceX) is
// wired but KEY-GATED via env — no key, no query, and the panel says so honestly.
//
// All HTTP goes through globalThis.fetch → undici global dispatcher, so the SOCKS
// proxy (when armed) covers OSINT egress exactly like every other recon path.
// Nothing here is an active probe of a target system: these are lookups against
// third-party public services, the same doctrine as the CVE/EPSS feed.

import { createHash } from 'crypto';
import { promises as dns } from 'dns';
import { directFetch } from '../net/proxy.js';
import type { Credential, CustomTool } from '../types/index.js';

const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const PROBE_TIMEOUT_MS = 8000;
const SWEEP_CONCURRENCY = 8;

async function osintFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return globalThis.fetch(url, {
    ...init,
    headers: { 'user-agent': UA, accept: 'text/html,application/json;q=0.9,*/*;q=0.8', ...(init.headers || {}) },
    signal: (init.signal as AbortSignal) || AbortSignal.timeout(PROBE_TIMEOUT_MS),
    redirect: 'follow',
  });
}

async function fetchJson<T = unknown>(url: string, init: RequestInit = {}): Promise<T | null> {
  try {
    const r = await osintFetch(url, init);
    if (!r.ok) return null;
    return (await r.json()) as T;
  } catch {
    return null;
  }
}

// =============================================================================
// SOCIAL SITE CATALOG
// =============================================================================
// probeType semantics:
//   status             → 2xx = FOUND, 404/410 = absent, anything else = unknown
//   body_contains      → 2xx AND body contains probeValue = FOUND; 2xx without it = absent
//                        (handles soft-404 pages like t.me's "no such user")
//   json_array_nonempty→ 2xx AND JSON array with length > 0 = FOUND; [] = absent
//   json_field         → 2xx AND object field (probeValue, dotted path) truthy = FOUND
// reliability: how much a FOUND can be trusted (login walls / soft-200s downgrade it)

export type OsintSiteCategory =
  | 'social' | 'dev' | 'gaming' | 'music' | 'art' | 'forum' | 'blog' | 'money' | 'video' | 'messaging';

export interface OsintSite {
  name: string;
  category: OsintSiteCategory;
  /** Human-viewable profile URL ({u} = username) */
  urlTemplate: string;
  /** URL actually probed — may differ (API endpoints give clean 404s) */
  probeUrlTemplate: string;
  probeType: 'status' | 'body_contains' | 'json_array_nonempty' | 'json_field';
  probeValue?: string;
  reliability: 'high' | 'medium' | 'low';
  notes?: string;
  /** Secondary probe when the primary is rate-limited/WAF-blocked (e.g. GitHub API 403 → HTML page). */
  fallbackProbeUrlTemplate?: string;
  fallbackProbeType?: OsintSite['probeType'];
  fallbackProbeValue?: string;
}

export const OSINT_SITES: OsintSite[] = [
  // --- developer / technical (strongest signals — clean API 404s) ---
  { name: 'GitHub', category: 'dev', urlTemplate: 'https://github.com/{u}', probeUrlTemplate: 'https://api.github.com/users/{u}', probeType: 'status', reliability: 'high', notes: 'GitHub REST API', fallbackProbeUrlTemplate: 'https://github.com/{u}', fallbackProbeType: 'body_contains', fallbackProbeValue: 'octolytics-dimension-user_login' },
  { name: 'GitLab', category: 'dev', urlTemplate: 'https://gitlab.com/{u}', probeUrlTemplate: 'https://gitlab.com/api/v4/users?username={u}', probeType: 'json_array_nonempty', reliability: 'high' },
  { name: 'Bitbucket', category: 'dev', urlTemplate: 'https://bitbucket.org/{u}/', probeUrlTemplate: 'https://api.bitbucket.org/2.0/users/{u}', probeType: 'status', reliability: 'high' },
  { name: 'npm', category: 'dev', urlTemplate: 'https://www.npmjs.com/~{u}', probeUrlTemplate: 'https://www.npmjs.com/~{u}', probeType: 'status', reliability: 'high' },
  { name: 'PyPI', category: 'dev', urlTemplate: 'https://pypi.org/user/{u}/', probeUrlTemplate: 'https://pypi.org/user/{u}/', probeType: 'status', reliability: 'medium' },
  { name: 'Docker Hub', category: 'dev', urlTemplate: 'https://hub.docker.com/u/{u}', probeUrlTemplate: 'https://hub.docker.com/u/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'SourceForge', category: 'dev', urlTemplate: 'https://sourceforge.net/u/{u}/profile/', probeUrlTemplate: 'https://sourceforge.net/u/{u}/profile/', probeType: 'status', reliability: 'medium' },
  { name: 'Replit', category: 'dev', urlTemplate: 'https://replit.com/@{u}', probeUrlTemplate: 'https://replit.com/@{u}', probeType: 'status', reliability: 'medium' },
  { name: 'CodePen', category: 'dev', urlTemplate: 'https://codepen.io/{u}', probeUrlTemplate: 'https://codepen.io/{u}', probeType: 'status', reliability: 'high' },
  { name: 'HackerOne', category: 'dev', urlTemplate: 'https://hackerone.com/{u}', probeUrlTemplate: 'https://hackerone.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Bugcrowd', category: 'dev', urlTemplate: 'https://bugcrowd.com/{u}', probeUrlTemplate: 'https://bugcrowd.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Hacker News', category: 'dev', urlTemplate: 'https://news.ycombinator.com/user?id={u}', probeUrlTemplate: 'https://hn.algolia.com/api/v1/users/{u}', probeType: 'status', reliability: 'high', notes: 'Algolia public API' },
  { name: 'dev.to', category: 'dev', urlTemplate: 'https://dev.to/{u}', probeUrlTemplate: 'https://dev.to/{u}', probeType: 'status', reliability: 'high' },
  { name: 'Medium', category: 'blog', urlTemplate: 'https://medium.com/@{u}', probeUrlTemplate: 'https://medium.com/@{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Hashnode', category: 'blog', urlTemplate: 'https://hashnode.com/@{u}', probeUrlTemplate: 'https://hashnode.com/@{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Substack', category: 'blog', urlTemplate: 'https://{u}.substack.com', probeUrlTemplate: 'https://{u}.substack.com', probeType: 'status', reliability: 'medium' },
  { name: 'WordPress.com', category: 'blog', urlTemplate: 'https://{u}.wordpress.com', probeUrlTemplate: 'https://{u}.wordpress.com', probeType: 'status', reliability: 'high' },
  { name: 'Pastebin', category: 'dev', urlTemplate: 'https://pastebin.com/u/{u}', probeUrlTemplate: 'https://pastebin.com/u/{u}', probeType: 'status', reliability: 'high' },
  { name: 'Trello', category: 'dev', urlTemplate: 'https://trello.com/{u}', probeUrlTemplate: 'https://trello.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Keybase', category: 'dev', urlTemplate: 'https://keybase.io/{u}', probeUrlTemplate: 'https://keybase.io/{u}', probeType: 'status', reliability: 'high', notes: 'Keybase profiles list linked identities' },

  // --- mainstream social ---
  { name: 'Reddit', category: 'social', urlTemplate: 'https://www.reddit.com/user/{u}', probeUrlTemplate: 'https://www.reddit.com/user/{u}/about.json', probeType: 'status', reliability: 'high', notes: 'Reddit about.json gives clean 404s' },
  { name: 'Instagram', category: 'social', urlTemplate: 'https://www.instagram.com/{u}/', probeUrlTemplate: 'https://www.instagram.com/{u}/', probeType: 'status', reliability: 'low', notes: 'login-wall often 200s — treat FOUND as weak' },
  { name: 'TikTok', category: 'video', urlTemplate: 'https://www.tiktok.com/@{u}', probeUrlTemplate: 'https://www.tiktok.com/@{u}', probeType: 'status', reliability: 'medium' },
  { name: 'X (Twitter)', category: 'social', urlTemplate: 'https://x.com/{u}', probeUrlTemplate: 'https://x.com/{u}', probeType: 'status', reliability: 'low', notes: 'logged-out serving is inconsistent by region' },
  { name: 'Threads', category: 'social', urlTemplate: 'https://www.threads.net/@{u}', probeUrlTemplate: 'https://www.threads.net/@{u}', probeType: 'status', reliability: 'low' },
  { name: 'Facebook', category: 'social', urlTemplate: 'https://www.facebook.com/{u}', probeUrlTemplate: 'https://www.facebook.com/{u}', probeType: 'status', reliability: 'low', notes: 'login wall' },
  { name: 'Mastodon (social)', category: 'social', urlTemplate: 'https://mastodon.social/@{u}', probeUrlTemplate: 'https://mastodon.social/@{u}', probeType: 'status', reliability: 'high' },
  { name: 'Bluesky', category: 'social', urlTemplate: 'https://bsky.app/profile/{u}', probeUrlTemplate: 'https://public.api.bsky.app/xrpc/app.bsky.actor.getProfiles?actors={u}', probeType: 'json_field', probeValue: 'profiles.0.did', reliability: 'high', notes: 'public AppView API' },
  { name: 'Telegram', category: 'messaging', urlTemplate: 'https://t.me/{u}', probeUrlTemplate: 'https://t.me/{u}', probeType: 'body_contains', probeValue: 'tgme_page_title', reliability: 'high', notes: 'soft-404 page stays 200 — body-detect needed' },
  { name: 'Pinterest', category: 'social', urlTemplate: 'https://www.pinterest.com/{u}/', probeUrlTemplate: 'https://www.pinterest.com/{u}/', probeType: 'status', reliability: 'medium' },
  { name: 'Tumblr', category: 'blog', urlTemplate: 'https://{u}.tumblr.com', probeUrlTemplate: 'https://{u}.tumblr.com', probeType: 'status', reliability: 'high' },
  { name: 'VK', category: 'social', urlTemplate: 'https://vk.com/{u}', probeUrlTemplate: 'https://vk.com/{u}', probeType: 'status', reliability: 'low', notes: 'auth wall' },
  { name: 'Truth Social', category: 'social', urlTemplate: 'https://truthsocial.com/@{u}', probeUrlTemplate: 'https://truthsocial.com/@{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Gab', category: 'social', urlTemplate: 'https://gab.com/{u}', probeUrlTemplate: 'https://gab.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Linktree', category: 'social', urlTemplate: 'https://linktr.ee/{u}', probeUrlTemplate: 'https://linktr.ee/{u}', probeType: 'status', reliability: 'high', notes: 'link hubs often reveal the full footprint' },
  { name: 'about.me', category: 'social', urlTemplate: 'https://about.me/{u}', probeUrlTemplate: 'https://about.me/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Gravatar', category: 'social', urlTemplate: 'https://gravatar.com/{u}', probeUrlTemplate: 'https://gravatar.com/{u}', probeType: 'status', reliability: 'medium', notes: 'profiles can list linked accounts' },
  { name: 'Imgur', category: 'social', urlTemplate: 'https://imgur.com/user/{u}', probeUrlTemplate: 'https://imgur.com/user/{u}', probeType: 'status', reliability: 'medium' },
  { name: '9GAG', category: 'social', urlTemplate: 'https://9gag.com/u/{u}', probeUrlTemplate: 'https://9gag.com/u/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Duolingo', category: 'social', urlTemplate: 'https://www.duolingo.com/profile/{u}', probeUrlTemplate: 'https://www.duolingo.com/profile/{u}', probeType: 'status', reliability: 'medium' },

  // --- streaming / video ---
  { name: 'Twitch', category: 'video', urlTemplate: 'https://www.twitch.tv/{u}', probeUrlTemplate: 'https://www.twitch.tv/{u}', probeType: 'status', reliability: 'high' },
  { name: 'YouTube', category: 'video', urlTemplate: 'https://www.youtube.com/@{u}', probeUrlTemplate: 'https://www.youtube.com/@{u}', probeType: 'status', reliability: 'medium', notes: 'handle pages 404 cleanly when unclaimed' },
  { name: 'Vimeo', category: 'video', urlTemplate: 'https://vimeo.com/{u}', probeUrlTemplate: 'https://vimeo.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Rumble', category: 'video', urlTemplate: 'https://rumble.com/user/{u}', probeUrlTemplate: 'https://rumble.com/user/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Odysee', category: 'video', urlTemplate: 'https://odysee.com/@{u}', probeUrlTemplate: 'https://odysee.com/@{u}', probeType: 'status', reliability: 'medium' },

  // --- music / audio ---
  { name: 'SoundCloud', category: 'music', urlTemplate: 'https://soundcloud.com/{u}', probeUrlTemplate: 'https://soundcloud.com/{u}', probeType: 'status', reliability: 'high' },
  { name: 'Last.fm', category: 'music', urlTemplate: 'https://www.last.fm/user/{u}', probeUrlTemplate: 'https://www.last.fm/user/{u}', probeType: 'status', reliability: 'high' },
  { name: 'Bandcamp', category: 'music', urlTemplate: 'https://{u}.bandcamp.com', probeUrlTemplate: 'https://{u}.bandcamp.com', probeType: 'status', reliability: 'high' },
  { name: 'Mixcloud', category: 'music', urlTemplate: 'https://www.mixcloud.com/{u}/', probeUrlTemplate: 'https://www.mixcloud.com/{u}/', probeType: 'status', reliability: 'medium' },

  // --- art / photography ---
  { name: 'DeviantArt', category: 'art', urlTemplate: 'https://www.deviantart.com/{u}', probeUrlTemplate: 'https://www.deviantart.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'ArtStation', category: 'art', urlTemplate: 'https://www.artstation.com/{u}', probeUrlTemplate: 'https://www.artstation.com/{u}', probeType: 'status', reliability: 'high' },
  { name: 'Behance', category: 'art', urlTemplate: 'https://www.behance.net/{u}', probeUrlTemplate: 'https://www.behance.net/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Dribbble', category: 'art', urlTemplate: 'https://dribbble.com/{u}', probeUrlTemplate: 'https://dribbble.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: '500px', category: 'art', urlTemplate: 'https://500px.com/p/{u}', probeUrlTemplate: 'https://500px.com/p/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Flickr', category: 'art', urlTemplate: 'https://www.flickr.com/people/{u}', probeUrlTemplate: 'https://www.flickr.com/people/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Unsplash', category: 'art', urlTemplate: 'https://unsplash.com/@{u}', probeUrlTemplate: 'https://unsplash.com/@{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Redbubble', category: 'art', urlTemplate: 'https://www.redbubble.com/people/{u}/shop', probeUrlTemplate: 'https://www.redbubble.com/people/{u}/shop', probeType: 'status', reliability: 'medium' },

  // --- gaming ---
  { name: 'Steam', category: 'gaming', urlTemplate: 'https://steamcommunity.com/id/{u}', probeUrlTemplate: 'https://steamcommunity.com/id/{u}', probeType: 'body_contains', probeValue: 'Invalid search term', reliability: 'medium', notes: 'ABSENT when that soft-404 string appears' },
  { name: 'chess.com', category: 'gaming', urlTemplate: 'https://www.chess.com/member/{u}', probeUrlTemplate: 'https://api.chess.com/pub/player/{u}', probeType: 'status', reliability: 'high', notes: 'public player API' },
  { name: 'Lichess', category: 'gaming', urlTemplate: 'https://lichess.org/@/{u}', probeUrlTemplate: 'https://lichess.org/@/{u}', probeType: 'status', reliability: 'high' },
  { name: 'HackerRank', category: 'gaming', urlTemplate: 'https://www.hackerrank.com/profile/{u}', probeUrlTemplate: 'https://www.hackerrank.com/profile/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'LeetCode', category: 'gaming', urlTemplate: 'https://leetcode.com/{u}/', probeUrlTemplate: 'https://leetcode.com/{u}/', probeType: 'status', reliability: 'medium' },
  { name: 'Minecraft (NameMC)', category: 'gaming', urlTemplate: 'https://namemc.com/profile/{u}', probeUrlTemplate: 'https://namemc.com/profile/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'speedrun.com', category: 'gaming', urlTemplate: 'https://speedrun.com/users/{u}', probeUrlTemplate: 'https://speedrun.com/api/v1/users?lookup={u}', probeType: 'json_array_nonempty', reliability: 'high' },

  // --- money / support ---
  { name: 'Patreon', category: 'money', urlTemplate: 'https://www.patreon.com/{u}', probeUrlTemplate: 'https://www.patreon.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Ko-fi', category: 'money', urlTemplate: 'https://ko-fi.com/{u}', probeUrlTemplate: 'https://ko-fi.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Buy Me a Coffee', category: 'money', urlTemplate: 'https://buymeacoff.ee/{u}', probeUrlTemplate: 'https://buymeacoff.ee/{u}', probeType: 'status', reliability: 'medium' },
];

// Steam's probe is inverted (the marker string means ABSENT) — encode via a
// dedicated probeType so the classifier stays dumb and correct.
type EffectiveProbeType = OsintSite['probeType'] | 'body_missing';

interface ResolvedSite extends OsintSite {
  effectiveProbeType: EffectiveProbeType;
}

function resolveSite(site: OsintSite): ResolvedSite {
  if (site.name === 'Steam') return { ...site, effectiveProbeType: 'body_missing' };
  return { ...site, effectiveProbeType: site.probeType };
}

export function normalizeUsername(raw: string): string {
  return raw.trim().replace(/^@+/, '').replace(/\/+$/, '');
}

export function validateUsername(username: string): string | null {
  const u = normalizeUsername(username);
  if (!u || u.length > 64 || /[/\\?#@\s]/.test(u)) return null;
  return u;
}

function dig(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const part of path.split('.')) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

export type IdentityMatch = 'name-match' | 'name-mismatch' | 'handle-only';

export interface ProfileHint {
  displayName?: string;
  bio?: string;
  imageUrl?: string;
  /** Public contact/location fields the platform exposes on the profile itself. */
  email?: string;
  blog?: string;
  twitter?: string;
  location?: string;
}

export interface UsernameHit {
  site: string;
  category: OsintSiteCategory;
  url: string;
  status: 'found' | 'absent' | 'unknown';
  confidence: 'high' | 'medium' | 'low';
  probeStatus?: number;
  note?: string;
  /** Profile details pulled from the platform's public API on a FOUND hit. */
  profile?: ProfileHint;
  /** Is this account corroborated as the subject, or just a claimed handle? */
  identity?: IdentityMatch;
}

/** Cheap public profile lookups for identity corroboration on FOUND hits. Each spec
 *  is URL + parser so the corroborator can run it via egress AND fall back to Tor. */
const PROFILE_APIS: Record<string, (u: string) => { url: string; parse: (j: unknown) => ProfileHint | null }> = {
  GitHub: (u) => ({
    url: `https://api.github.com/users/${encodeURIComponent(u)}`,
    parse: (j) => {
      const r = j as Record<string, string | null>;
      if (!r || (!r.name && !r.avatar_url && !r.email)) return null;
      return {
        displayName: (r.name as string) || undefined,
        bio: (r.bio as string) || undefined,
        imageUrl: (r.avatar_url as string) || undefined,
        email: (r.email as string) || undefined,
        blog: (r.blog as string) || undefined,
        twitter: (r.twitter_username as string) ? `https://x.com/${r.twitter_username}` : undefined,
        location: (r.location as string) || undefined,
      };
    },
  }),
  Reddit: (u) => ({
    url: `https://www.reddit.com/user/${encodeURIComponent(u)}/about.json`,
    parse: (j) => {
      const data = (j as { data?: { name?: string; title?: string; icon_img?: string } })?.data;
      return data ? { displayName: data.title || data.name || undefined, imageUrl: data.icon_img || undefined } : null;
    },
  }),
  'chess.com': (u) => ({
    url: `https://api.chess.com/pub/player/${encodeURIComponent(u)}`,
    parse: (j) => {
      const r = j as { name?: string; avatar?: string };
      return r ? { displayName: r.name || undefined, imageUrl: r.avatar || undefined } : null;
    },
  }),
  'dev.to': (u) => ({
    url: `https://dev.to/api/users/by_username?url=${encodeURIComponent(u)}`,
    parse: (j) => {
      const r = j as { username?: string; name?: string; profile_image?: string; summary?: string };
      return r?.username ? { displayName: r.name || undefined, imageUrl: r.profile_image || undefined, bio: r.summary || undefined } : null;
    },
  }),
  Lichess: (u) => ({
    url: `https://lichess.org/api/user/${encodeURIComponent(u)}`,
    parse: (j) => {
      const r = j as { profile?: { fullName?: string; bio?: string }; lastName?: string; firstName?: string };
      if (!r) return null;
      const fullName = r.profile?.fullName || [r.firstName, r.lastName].filter(Boolean).join(' ') || undefined;
      return { displayName: fullName || undefined, bio: r.profile?.bio || undefined };
    },
  }),
  'Hacker News': (u) => ({
    url: `https://hn.algolia.com/api/v1/users/${encodeURIComponent(u)}`,
    parse: (j) => ((j as { id?: string })?.id ? {} : null),
  }),
};

async function corroborate(siteName: string, username: string): Promise<ProfileHint | null> {
  const spec = PROFILE_APIS[siteName];
  if (!spec) return null;
  const { url, parse } = spec(username);
  try {
    const j = await fetchJson<unknown>(url);
    const hint = j ? parse(j) : null;
    if (hint) return hint;
  } catch { /* fall through to Tor */ }
  const tor = await torStatus();
  if (tor.available) {
    try {
      const page = await torFetchAny(url);
      if (page.status === 200) return parse(JSON.parse(page.body));
    } catch { /* fall through to direct */ }
  }
  if (directAllowed()) {
    try {
      const res = await directFetch(url, {
        headers: { 'user-agent': UA, accept: 'application/json' },
        signal: AbortSignal.timeout(12_000),
      } as never);
      if (res.status === 200) return parse(await res.json());
    } catch { /* all paths failed — handle-only */ }
  }
  return null;
}

/** Corroborate a claimed handle against the subject's known name. Pure function.
 *  'name-match'    = display name/bio carries the subject's LAST name (full or
 *                    substring — initials-style 'jsmith' counts), or the full name.
 *  'name-mismatch' = profile has a display name that does NOT carry the last name
 *                    (e.g. subject 'Raul Glasgow', profile 'Raul Gutierrez' — a
 *                    first-name-only overlap is a DIFFERENT person, never a match).
 *  'handle-only'   = no name hints, ambiguous initial-only, or no name to compare. */
export function scoreIdentityMatch(hints: { name?: string }, profile?: ProfileHint | null): IdentityMatch {
  const hintName = (hints.name || '').toLowerCase().replace(/[^a-z ]/g, ' ').replace(/\s+/g, ' ').trim();
  if (!hintName || !hintName.includes(' ')) return 'handle-only'; // need a real full name to corroborate
  const hTokens = hintName.split(' ').filter((t) => t.length > 1);
  const lastName = hTokens[hTokens.length - 1];
  const dn = (profile?.displayName || '').toLowerCase().replace(/[^a-z ]/g, ' ').replace(/\s+/g, ' ').trim();
  const dTokens = dn ? dn.split(' ').filter((t) => t.length > 1) : [];
  const sub = (a: string, b: string) => a.includes(b) || b.includes(a);

  if (dTokens.length > 0) {
    if (hTokens.every((t) => dTokens.includes(t))) return 'name-match';
    // Last name present (exact, or substring of/into a real name fragment ≥3 chars —
    // initials like 't' never substring-match).
    if (dTokens.some((d) => d === lastName || (d.length >= 3 && (d.includes(lastName) || lastName.includes(d))))) return 'name-match';
    const firstOverlap = hTokens.slice(0, -1).some((t) => dTokens.some((d) => sub(d, t)));
    if (firstOverlap) return 'name-mismatch'; // shares a first name only — different person (initial-only ambiguity excluded too)
    return 'name-mismatch';
  }
  const bio = (profile?.bio || '').toLowerCase();
  if (bio && hTokens.every((t) => bio.includes(t))) return 'name-match';
  return dn ? 'name-mismatch' : 'handle-only';
}

interface ProbeOutcome { status: number; body?: string; via: 'egress' | 'tor'; url: string; note?: string }

function classifyOutcome(site: ResolvedSite, outcome: ProbeOutcome): Pick<UsernameHit, 'status' | 'probeStatus' | 'note'> {
  const ok = outcome.status >= 200 && outcome.status < 300;
  let status: UsernameHit['status'] = 'unknown';
  if (site.effectiveProbeType === 'status') {
    if (ok) status = 'found';
    else if (outcome.status === 404 || outcome.status === 410) status = 'absent';
  } else if (ok) {
    const body = outcome.body ?? '';
    const has = site.probeValue ? body.includes(site.probeValue) : false;
    if (site.effectiveProbeType === 'body_contains') status = has ? 'found' : 'absent';
    else if (site.effectiveProbeType === 'body_missing') status = has ? 'absent' : 'found';
    else if (site.effectiveProbeType === 'json_array_nonempty') {
      try { status = Array.isArray(JSON.parse(body || '[]')) && JSON.parse(body).length > 0 ? 'found' : 'absent'; } catch { status = 'unknown'; }
    } else if (site.effectiveProbeType === 'json_field') {
      try { status = dig(JSON.parse(body || '{}'), site.probeValue || '') ? 'found' : 'absent'; } catch { status = 'unknown'; }
    }
  } else if (outcome.status === 404 || outcome.status === 410) {
    status = 'absent';
  }
  const note = outcome.via === 'tor' ? 'probe via Tor circuit' : outcome.note;
  return { status, probeStatus: outcome.status, note };
}

async function probeEgress(url: string, readBody: boolean): Promise<ProbeOutcome> {
  const res = await osintFetch(url);
  const body = readBody ? (await res.text().catch(() => '')).slice(0, 300_000) : undefined;
  return { status: res.status, body, url, via: 'egress' };
}

async function probeViaTor(url: string): Promise<ProbeOutcome | null> {
  const tor = await torStatus();
  if (!tor.available) return null;
  try {
    const page = await torFetchAny(url);
    return { status: page.status, body: page.body.slice(0, 300_000), url, via: 'tor' };
  } catch {
    return null;
  }
}

/** Last-resort path for third-party OSINT lookups: connect DIRECT (real IP visible
 *  to the data platform — not a mission target). Kill-switch: T3MP3ST_OSINT_ALLOW_DIRECT=0. */
function directAllowed(): boolean {
  return !/^(0|false|no|off)$/i.test(process.env.T3MP3ST_OSINT_ALLOW_DIRECT ?? '1');
}

async function probeDirect(url: string, readBody: boolean): Promise<ProbeOutcome | null> {
  if (!directAllowed()) return null;
  try {
    const res = await directFetch(url, {
      headers: { 'user-agent': UA, accept: 'text/html,application/json;q=0.9,*/*;q=0.8' },
      signal: AbortSignal.timeout(15_000),
      redirect: 'follow',
    } as never);
    const body = readBody ? (await res.text().catch(() => '')).slice(0, 300_000) : undefined;
    return { status: res.status, body, url, via: 'egress', note: '⚠ direct connection (real IP seen by platform) — set T3MP3ST_OSINT_ALLOW_DIRECT=0 to disable' };
  } catch {
    return null;
  }
}

/** Extract a display name from a GitHub profile HTML page (fallback path when the API is rate-limited). */
function githubDisplayNameFromHtml(html: string, username: string): string | undefined {
  const title = html.match(/<title>([^<]+)<\/title>/)?.[1] || '';
  const m = title.match(new RegExp(`${username} \\(([^)]+)\\)`, 'i'));
  return m?.[1] || undefined;
}

async function probeSite(site: ResolvedSite, username: string, hints?: { name?: string }): Promise<UsernameHit> {
  const enc = encodeURIComponent(username).replace(/%40/g, '@');
  const url = site.probeUrlTemplate.replaceAll('{u}', enc);
  const humanUrl = site.urlTemplate.replaceAll('{u}', enc);
  const base: UsernameHit = {
    site: site.name,
    category: site.category,
    url: humanUrl,
    status: 'unknown',
    confidence: site.reliability,
  };

  // — Pass 1: primary probe over normal egress —
  let outcome: ProbeOutcome | null = null;
  try {
    const needsBody = site.effectiveProbeType !== 'status';
    const first = await probeEgress(url, needsBody);
    if (first.status === 403 || first.status === 429 || first.status >= 500) outcome = null; // unclear — escalate
    else outcome = first;
  } catch {
    outcome = null;
  }

  // — Pass 2: fallback probe (e.g. HTML page when the JSON API is rate-limited) —
  let usedFallback = false;
  if (!outcome && site.fallbackProbeUrlTemplate) {
    try {
      const fbUrl = site.fallbackProbeUrlTemplate.replaceAll('{u}', enc);
      const res = await osintFetch(fbUrl, { signal: AbortSignal.timeout(18_000) });
      if (res.status === 200 || res.status === 404 || res.status === 410) {
        const text = res.status === 200 ? (await res.text().catch(() => '')).slice(0, 300_000) : '';
        usedFallback = true;
        outcome = { status: res.status, body: text, url: fbUrl, via: 'egress', note: 'API rate-limited — classified via HTML page' };
      }
    } catch { /* fallback failed — escalate to Tor */ }
  }

  // — Pass 3: primary probe over the Tor circuit (fresh exit beats WAF blocks) —
  if (!outcome) {
    outcome = (await probeViaTor(site.fallbackProbeUrlTemplate?.replaceAll('{u}', enc) || url))
      || (await probeViaTor(url));
  }

  // — Pass 4: direct connection (real IP) — accuracy lever for platforms that
  //   rate-limit/block the shared proxy and Tor exits. Marked on the hit. —
  if (!outcome && directAllowed()) {
    try {
      const needsBody = (usedFallback ? (site.fallbackProbeType || site.effectiveProbeType) : site.effectiveProbeType) !== 'status';
      const probeUrl = (usedFallback ? site.fallbackProbeUrlTemplate : site.probeUrlTemplate)?.replaceAll('{u}', enc) || url;
      outcome = await probeDirect(probeUrl, needsBody);
    } catch { /* direct failed too */ }
  }

  if (!outcome) {
    base.note = 'unreachable via egress, Tor and direct (set T3MP3ST_OSINT_ALLOW_DIRECT=1 — default on)';
    return base;
  }

  // — Classify —
  const eff: ResolvedSite = usedFallback
    ? { ...site, effectiveProbeType: (site.fallbackProbeType || site.effectiveProbeType) as EffectiveProbeType, probeValue: site.fallbackProbeValue || site.probeValue }
    : site;
  const classified = classifyOutcome(eff, outcome);
  Object.assign(base, classified);

  // — Corroborate identity on FOUND hits —
  if (base.status === 'found') {
    let profile: ProfileHint | null = null;
    if (usedFallback && site.name === 'GitHub' && outcome.body) {
      const dn = githubDisplayNameFromHtml(outcome.body, username);
      if (dn) profile = { displayName: dn };
    }
    if (!profile && PROFILE_APIS[site.name]) {
      profile = await corroborate(site.name, username);
    }
    if (profile) base.profile = profile;
    base.identity = scoreIdentityMatch(hints || {}, profile);
  }
  return base;
}

export interface SweepResult {
  username: string;
  found: UsernameHit[];
  absent: number;
  unknown: UsernameHit[];
  checked: number;
  /** Per-site probe results (found/absent/unknown) — the sources-consulted audit trail. */
  details: UsernameHit[];
  durationMs: number;
}

/** Concurrent username sweep across the public-profile catalog (Sherlock-style, keyless).
 *  `customSites` (test/harness hook) probes caller-supplied site specs instead of the
 *  catalog — used by the unit tests to exercise the classifier against a local stub. */
export async function runUsernameSweep(
  usernameRaw: string,
  opts: { sites?: string[]; categories?: OsintSiteCategory[]; limit?: number; customSites?: OsintSite[]; hints?: { name?: string } } = {}
): Promise<SweepResult> {
  const started = Date.now();
  const username = validateUsername(usernameRaw);
  if (!username) throw new Error(`Invalid username: ${usernameRaw}`);

  let sites: ResolvedSite[];
  if (opts.customSites?.length) {
    sites = opts.customSites.map(resolveSite);
  } else {
    sites = OSINT_SITES.map(resolveSite);
    if (opts.sites?.length) {
      const wanted = new Set(opts.sites.map((s) => s.toLowerCase()));
      sites = sites.filter((s) => wanted.has(s.name.toLowerCase()));
    }
    if (opts.categories?.length) {
      const cats = new Set(opts.categories);
      sites = sites.filter((s) => cats.has(s.category));
    }
    if (opts.limit && opts.limit > 0) sites = sites.slice(0, opts.limit);
  }
  if (sites.length === 0) throw new Error('No sites to probe — check the site filter');

  const results: UsernameHit[] = [];
  for (let i = 0; i < sites.length; i += SWEEP_CONCURRENCY) {
    const batch = sites.slice(i, i + SWEEP_CONCURRENCY);
    results.push(...(await Promise.all(batch.map((s) => probeSite(s, username, opts.hints)))));
  }

  const found = results.filter((r) => r.status === 'found');
  const unknown = results.filter((r) => r.status === 'unknown');
  return {
    username,
    found,
    absent: results.filter((r) => r.status === 'absent').length,
    unknown,
    checked: results.length,
    details: results,
    durationMs: Date.now() - started,
  };
}

// =============================================================================
// EMAIL INTEL — Gravatar identity + breach exposure (all keyless)
// =============================================================================

export interface GravatarProfile {
  hash: string;
  exists: boolean;
  avatarUrl: string;
  displayName?: string;
  about?: string;
  location?: string;
  links?: { title?: string; url: string }[];
  accounts?: { shortname: string; url: string; username?: string }[];
}

interface GravatarEntry {
  entry?: {
    hash?: string;
    displayName?: string;
    aboutMe?: string;
    currentLocation?: string;
    links?: { title?: string; url?: string }[];
    accounts?: { shortname?: string; url?: string; username?: string }[];
  }[];
}

export async function gravatarProfile(email: string): Promise<GravatarProfile> {
  const hash = createHash('md5').update(email.trim().toLowerCase()).digest('hex');
  const profile: GravatarProfile = {
    hash,
    exists: false,
    avatarUrl: `https://www.gravatar.com/avatar/${hash}?s=256`,
  };
  try {
    const avatarCheck = await osintFetch(`https://www.gravatar.com/avatar/${hash}?d=404&s=1`);
    profile.exists = avatarCheck.ok;
  } catch {
    /* network hiccup — leave exists=false but try the profile JSON anyway */
  }
  const data = await fetchJson<GravatarEntry>(`https://www.gravatar.com/${hash}.json`);
  const entry = data?.entry?.[0];
  if (entry) {
    profile.displayName = entry.displayName;
    profile.about = entry.aboutMe;
    profile.location = entry.currentLocation;
    profile.links = (entry.links || []).filter((l): l is { title?: string; url: string } => Boolean(l.url));
    profile.accounts = (entry.accounts || []).filter((a): a is { shortname: string; url: string; username?: string } => Boolean(a.url));
  }
  return profile;
}

export interface BreachSummary {
  service: string;
  found: number | 'unknown';
  fields?: string[];
  sources?: string[];
  note?: string;
}

interface LeakcheckPublicResponse { success?: boolean; found?: number; fields?: string[]; sources?: { name: string; date: string }[] }
interface XposedornotResponse { exposed?: string; breaches?: string[][]; breach?: string[] }

export async function leakcheckPublic(query: string): Promise<BreachSummary> {
  const r = await osintFetch(`https://leakcheck.io/api/public?check=${encodeURIComponent(query)}`);
  if (r.status === 429) return { service: 'LeakCheck', found: 'unknown', note: 'rate-limited — free lane allows ~1 query/10s' };
  const j = (await r.json().catch(() => ({}))) as LeakcheckPublicResponse;
  if (!j.success || !j.found) return { service: 'LeakCheck', found: 0 };
  return {
    service: 'LeakCheck',
    found: j.found,
    fields: j.fields || [],
    sources: (j.sources || []).slice(0, 10).map((s) => `${s.name} (${s.date})`),
    note: 'public API: counts + sources only — full dump records need a LeakCheck key',
  };
}

export async function xposedOrNot(email: string): Promise<BreachSummary> {
  const r = await osintFetch(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`);
  const j = (await r.json().catch(() => ({}))) as XposedornotResponse;
  const list = j.breaches?.[0] ?? j.breach ?? [];
  if (j.exposed === 'Not Found' || !Array.isArray(list) || list.length === 0) {
    return { service: 'XposedOrNot', found: 0 };
  }
  return { service: 'XposedOrNot', found: list.length, sources: list.slice(0, 25) };
}

export async function pwnedPasswordCount(password: string): Promise<number> {
  const sha1 = createHash('sha1').update(password).digest('hex').toUpperCase();
  const r = await osintFetch(`https://api.pwnedpasswords.com/range/${sha1.slice(0, 5)}`);
  const text = await r.text();
  for (const line of text.split('\n')) {
    const [suffix, count] = line.trim().split(':');
    if (suffix === sha1.slice(5)) return parseInt(count, 10) || 0;
  }
  return 0;
}

// --- NEW keyless lanes: Hudson Rock (live infostealer infections) + HIBP catalogue ---
// Hudson Rock's free cybercrime-intelligence feed: real infostealer infection records
// (family, date, computer name, IP, OS, installed software) — a live-compromise class
// the static dump lanes can't see. HIBP's breach catalogue (haveibeenpwned.com/api/v3/
// breaches) is keyless and answers "was this domain ever breached" with pwn counts.

export interface InfostealerHit {
  family?: string;
  date?: string;
  computerName?: string;
  ip?: string;
  os?: string;
  software?: string[];
  url?: string;
}
export interface HudsonRockResult {
  service: 'Hudson Rock';
  infected: boolean;
  infections: InfostealerHit[];
  corporateServices: number;
  userServices: number;
  note?: string;
}

export function parseHudsonRock(j: unknown): HudsonRockResult {
  const o = (j || {}) as Record<string, unknown>;
  const raw = Array.isArray(o.stealers) ? (o.stealers as Record<string, unknown>[]) : [];
  const pick = (r: Record<string, unknown>, ...keys: string[]): string | undefined => {
    for (const k of keys) { const v = r[k]; if (typeof v === 'string' && v.trim()) return v.trim(); }
    return undefined;
  };
  const strArray = (r: Record<string, unknown>, ...keys: string[]): string[] | undefined => {
    for (const k of keys) if (Array.isArray(r[k])) return (r[k] as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 12);
    return undefined;
  };
  const infections: InfostealerHit[] = raw.slice(0, 10).map((r) => ({
    family: pick(r, 'stealer_family', 'stealerFamily', 'family', 'malware'),
    date: pick(r, 'date_compromised', 'dateCompromised', 'date', 'compromise_date'),
    computerName: pick(r, 'computer_name', 'computerName', 'hostname'),
    ip: pick(r, 'ip_address', 'ipAddress', 'ip'),
    os: pick(r, 'operating_system', 'operatingSystem', 'os'),
    software: strArray(r, 'installed_software', 'installedSoftware'),
    url: pick(r, 'url', 'c2_url', 'malicious_url'),
  }));
  return {
    service: 'Hudson Rock',
    infected: infections.length > 0,
    infections,
    corporateServices: typeof o.total_corporate_services === 'number' ? o.total_corporate_services : 0,
    userServices: typeof o.total_user_services === 'number' ? o.total_user_services : 0,
    note: infections.length === 0 && typeof o.message === 'string' ? o.message.slice(0, 160) : undefined,
  };
}

export async function hudsonRockEmail(emailRaw: string): Promise<HudsonRockResult> {
  const email = emailRaw.trim().toLowerCase();
  if (!EMAIL_RE.test(email)) throw new Error(`Invalid email address: ${emailRaw}`);
  const j = await osintJsonWithFallback<unknown>(`https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=${encodeURIComponent(email)}`);
  if (!j) return { service: 'Hudson Rock', infected: false, infections: [], corporateServices: 0, userServices: 0, note: 'lane unavailable (egress/Tor/direct all failed)' };
  return parseHudsonRock(j);
}

export interface HibpCatalogEntry {
  name: string; title: string; domain?: string; breachDate?: string; addedDate?: string;
  modifiedDate?: string; pwnCount?: number; description?: string; dataClasses?: string[]; isVerified?: boolean;
}

export function parseHibpCatalog(j: unknown): HibpCatalogEntry[] {
  if (!Array.isArray(j)) return [];
  return (j as Record<string, unknown>[]).slice(0, 800).map((e) => ({
    name: String(e.Name || ''),
    title: String(e.Title || e.Name || ''),
    domain: typeof e.Domain === 'string' ? e.Domain : undefined,
    breachDate: typeof e.BreachDate === 'string' ? e.BreachDate : undefined,
    addedDate: typeof e.AddedDate === 'string' ? e.AddedDate : undefined,
    modifiedDate: typeof e.ModifiedDate === 'string' ? e.ModifiedDate : undefined,
    pwnCount: typeof e.PwnCount === 'number' ? e.PwnCount : undefined,
    description: typeof e.Description === 'string' ? e.Description.slice(0, 400) : undefined,
    dataClasses: Array.isArray(e.DataClasses) ? (e.DataClasses as unknown[]).filter((x): x is string => typeof x === 'string') : undefined,
    isVerified: typeof e.IsVerified === 'boolean' ? e.IsVerified : undefined,
  }));
}

const hibpCatalogCache = new Map<string, { at: number; entries: HibpCatalogEntry[] }>();

/** HIBP breach catalogue — keyless, 24h cache. Optional domain filter (?Domain=). */
export async function hibpBreachCatalog(domainRaw?: string): Promise<{ domain: string | null; total: number; entries: HibpCatalogEntry[]; note?: string }> {
  const domain = (domainRaw || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (domainRaw && domain && !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new Error(`Invalid domain: ${domainRaw}`);
  const key = domain || '*';
  const hit = hibpCatalogCache.get(key);
  if (hit && Date.now() - hit.at < 86_400_000) return { domain: domain || null, total: hit.entries.length, entries: hit.entries };
  const j = await osintJsonWithFallback<unknown>(
    `https://haveibeenpwned.com/api/v3/breaches${domain ? `?Domain=${encodeURIComponent(domain)}` : ''}`,
    {},
    { 'user-agent': 'T3MP3ST-OSINT/1.0' }
  );
  if (!j) return { domain: domain || null, total: 0, entries: [], note: 'lane unavailable (HIBP unreachable)' };
  const entries = parseHibpCatalog(j);
  hibpCatalogCache.set(key, { at: Date.now(), entries });
  return { domain: domain || null, total: entries.length, entries };
}

export interface EmailIntelResult {
  email: string;
  valid: boolean;
  gravatar: GravatarProfile;
  breaches: BreachSummary[];
  infostealer: HudsonRockResult;
  domain: { name: string; mxRecords: string[]; aRecord?: string; acceptsMail: boolean } | null;
}

const EMAIL_RE = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;

export async function emailIntel(emailRaw: string): Promise<EmailIntelResult> {
  const email = emailRaw.trim().toLowerCase();
  if (!EMAIL_RE.test(email)) throw new Error(`Invalid email address: ${emailRaw}`);
  const [, domain] = email.split('@');

  const [gravatar, lc, xo, hr, mx, a] = await Promise.all([
    gravatarProfile(email),
    leakcheckPublic(email).catch((e): BreachSummary => ({ service: 'LeakCheck', found: 'unknown', note: String(e).slice(0, 100) })),
    xposedOrNot(email).catch((e): BreachSummary => ({ service: 'XposedOrNot', found: 'unknown', note: String(e).slice(0, 100) })),
    hudsonRockEmail(email).catch((e): HudsonRockResult => ({ service: 'Hudson Rock', infected: false, infections: [], corporateServices: 0, userServices: 0, note: String(e).slice(0, 100) })),
    dns.resolveMx(domain).catch(() => [] as { exchange: string; priority: number }[]),
    dns.resolve4(domain).then((r) => r[0]).catch(() => undefined),
  ]);

  const hrSummary: BreachSummary = {
    service: 'Hudson Rock (infostealers)',
    found: hr.infected ? hr.infections.length : 0,
    sources: [...new Set(hr.infections.map((i) => i.family).filter((f): f is string => Boolean(f)))],
    note: hr.infected ? `LIVE infostealer infection on record (${hr.corporateServices} corporate / ${hr.userServices} user services exposed)` : hr.note,
  };

  return {
    email,
    valid: true,
    gravatar,
    breaches: [xo, lc, hrSummary],
    infostealer: hr,
    domain: {
      name: domain,
      mxRecords: mx.map((m) => m.exchange).slice(0, 5),
      aRecord: a,
      acceptsMail: mx.length > 0,
    },
  };
}

// =============================================================================
// DARK WEB / DUMP DATABASES — free lanes live, deep lanes key-gated
// =============================================================================

interface DumpRecord {
  service: string;
  found: number;
  records?: {
    email?: string; username?: string; password?: string; hash?: string; source?: string; date?: string;
    /** Identity fields the licensed dump services return when the source dump had them. */
    dob?: string; age?: string; address?: string; city?: string; state?: string; country?: string; phone?: string;
  }[];
  note?: string;
}

// --- runtime dump-lane keys (Settings-persisted; env fallback) ----------------
// Keys arm LeakCheck v2 / DeHashed / Snusbase instantly from the UI — no restart.
// Stored via the server's settings DB (memory/db-settings.json, gitignored) and
// masked in every GET. No Tor dump-site harvesters: licensed services only.

type DumpKeyService = 'leakcheck' | 'dehashed' | 'snusbase';
const DUMP_KEY_SERVICES: DumpKeyService[] = ['leakcheck', 'dehashed', 'snusbase'];
const dumpKeys: Partial<Record<DumpKeyService, string>> = {};
const DUMP_ENV: Record<DumpKeyService, string> = {
  leakcheck: 'T3MP3ST_LEAKCHECK_KEY',
  dehashed: 'T3MP3ST_DEHASHED_KEY',
  snusbase: 'T3MP3ST_SNUSBASE_KEY',
};

export function setDumpKey(service: DumpKeyService, key: string | undefined): void {
  if (key && key.trim()) dumpKeys[service] = key.trim();
  else delete dumpKeys[service];
}

export function getDumpKey(service: DumpKeyService): string | undefined {
  return dumpKeys[service] || process.env[DUMP_ENV[service]] || undefined;
}

export function dumpKeyStatus(): Record<DumpKeyService, boolean> {
  return {
    leakcheck: Boolean(getDumpKey('leakcheck')),
    dehashed: Boolean(getDumpKey('dehashed')),
    snusbase: Boolean(getDumpKey('snusbase')),
  };
}

export function isDumpKeyService(v: string): v is DumpKeyService {
  return (DUMP_KEY_SERVICES as string[]).includes(v);
}

/** JSON fetch with the full fallback chain (egress → Tor → direct). The dump APIs
 *  are third-party data platforms, not mission targets — the direct leg keeps them
 *  usable when the shared proxy exit is blocked, and it is marked/kill-switched.
 *  Any transport whose response parses as JSON wins (API-level errors like
 *  "invalid key" arrive as JSON too — callers interpret the payload). */
async function osintJsonWithFallback<T>(url: string, init: RequestInit = {}, headers: Record<string, string> = {}): Promise<T | null> {
  const tryParse = (raw: string): T | null => {
    const t = raw.trim();
    if (!t.startsWith('{') && !t.startsWith('[')) return null;
    try { return JSON.parse(t) as T; } catch { return null; }
  };
  try {
    const res = await osintFetch(url, { ...init, headers });
    const j = tryParse(await res.text().catch(() => ''));
    if (j) return j;
  } catch { /* fall through */ }
  const tor = await torStatus();
  if (tor.available) {
    try {
      const page = await torFetchAny(url);
      const j = tryParse(page.body);
      if (j) return j;
    } catch { /* fall through */ }
  }
  if (directAllowed()) {
    try {
      const res = await directFetch(url, {
        headers: { 'user-agent': UA, accept: 'application/json', ...headers },
        signal: AbortSignal.timeout(15_000),
      } as never);
      const j = tryParse(await res.text().catch(() => ''));
      if (j) return j;
    } catch { /* all paths failed */ }
  }
  return null;
}

/** LeakCheck v2 — full records (incl. password fields when the dump has them). Key-gated. */
async function leakcheckDeep(query: string, kind: 'email' | 'username' | 'phone' | 'domain'): Promise<DumpRecord | null> {
  const key = getDumpKey('leakcheck');
  if (!key) return null;
  const j = await osintJsonWithFallback<{ success?: boolean; found?: number; result?: Record<string, string>[]; error?: string }>(
    `https://leakcheck.io/api/v2/query/${encodeURIComponent(query)}?type=${kind}`,
    {},
    { 'X-API-Key': key }
  );
  if (!j) return { service: 'LeakCheck v2 (keyed)', found: 0, note: 'API unreachable via egress, Tor and direct' };
  if (j.success === false || j.error) {
    return { service: 'LeakCheck v2 (keyed)', found: 0, note: `LeakCheck API: ${j.error || 'request rejected'}` };
  }
  return {
    service: 'LeakCheck v2 (keyed)',
    found: j.found ?? 0,
    records: (j.result || []).slice(0, 50).map((rec) => ({
      email: rec.email, username: rec.username, password: rec.password, hash: rec.hashed_password,
      dob: rec.date_of_birth || rec.dob, address: rec.address, city: rec.city, state: rec.state,
      country: rec.country, phone: rec.phone,
      source: rec.sources?.replace(/;/g, ', '),
    })),
  };
}

/** DeHashed — deep-web breach search. Key-gated (basic auth user:key). */
async function dehashedDeep(query: string, kind: 'email' | 'username' | 'phone'): Promise<DumpRecord | null> {
  const key = getDumpKey('dehashed');
  if (!key) return null;
  const j = await osintJsonWithFallback<{ total?: number; entries?: Record<string, string | null>[] }>(
    `https://api.dehashed.com/search?query=${encodeURIComponent(`${kind}:"${query}"`)}&size=50`,
    {},
    { authorization: `Basic ${Buffer.from(key).toString('base64')}` }
  );
  if (!j) return { service: 'DeHashed (keyed)', found: 0, note: 'API unreachable via egress, Tor and direct' };
  const str = (v: string | null | undefined): string | undefined => (typeof v === 'string' && v.trim() ? v.trim() : undefined);
  return {
    service: 'DeHashed (keyed)',
    found: j.total ?? 0,
    records: (j.entries || []).slice(0, 50).map((e) => ({
      email: str(e.email), username: str(e.username), password: str(e.password), hash: str(e.hashed_password),
      dob: str(e.date_of_birth) || str(e.dob), age: str(e.age), address: str(e.address), city: str(e.city),
      state: str(e.state), country: str(e.country), phone: str(e.phone),
      source: str(e.database),
    })),
  };
}

/** Snusbase — dump database. Key-gated. */
async function snusbaseDeep(query: string, kind: 'email' | 'username' | 'phone'): Promise<DumpRecord | null> {
  const key = getDumpKey('snusbase');
  if (!key) return null;
  const j = await osintJsonWithFallback<{ result?: Record<string, string>[] }>(
    `https://api.snusbase.com/v2/user/search?type=${kind}&term=${encodeURIComponent(query)}`,
    {},
    { auth: key }
  );
  if (!j) return { service: 'Snusbase (keyed)', found: 0, note: 'API unreachable via egress, Tor and direct' };
  const records = (j.result || []).slice(0, 50);
  return {
    service: 'Snusbase (keyed)',
    found: records.length,
    records: records.map((e) => ({
      email: e.email, username: e.username, password: e.password, hash: e.passhash || e.hash,
      dob: e.dob || e.date_of_birth, address: e.address, city: e.city, state: e.state,
      country: e.country, phone: e.phone,
      source: e.database,
    })),
  };
}

export interface DumpLaneResult {
  query: string;
  kind: 'email' | 'username' | 'phone' | 'password';
  free: BreachSummary[];
  deep: (DumpRecord | { service: string; status: 'key-required'; note: string })[];
  credentials: Credential[];
}

/**
 * Full dump-database pass on a subject. Free lanes (LeakCheck public, XposedOrNot,
 * Pwned Passwords) always run; the deep dump lanes run when the operator configured
 * keys. Password material that comes back is minted as Credential records so it lands
 * in the Evidence Vault credential ledger.
 */
export async function dumpDatabaseLookup(
  queryRaw: string,
  kind: 'email' | 'username' | 'phone' | 'password'
): Promise<DumpLaneResult> {
  const query = queryRaw.trim();
  const free: BreachSummary[] = [];
  const deep: DumpLaneResult['deep'] = [];
  const credentials: Credential[] = [];

  if (kind === 'password') {
    const count = await pwnedPasswordCount(query);
    free.push({
      service: 'HIBP Pwned Passwords',
      found: count,
      note: count > 0
        ? `Password appears in ${count} breached records — NEVER use it in an engagement guess without authorization`
        : 'Password not present in the Pwned Passwords corpus',
    });
  } else {
    free.push(await leakcheckPublic(query).catch((e): BreachSummary => ({ service: 'LeakCheck', found: 'unknown', note: String(e).slice(0, 100) })));
    if (kind === 'email') {
      free.push(await xposedOrNot(query).catch((e): BreachSummary => ({ service: 'XposedOrNot', found: 'unknown', note: String(e).slice(0, 100) })));
    }
    const lanes: Promise<DumpRecord | null>[] = [];
    if (kind === 'phone') {
      lanes.push(leakcheckDeep(query, kind));
      lanes.push(snusbaseDeep(query, kind));
    } else {
      lanes.push(leakcheckDeep(query, kind));
      lanes.push(dehashedDeep(query, kind));
      lanes.push(snusbaseDeep(query, kind));
    }
    const settled = await Promise.all(lanes.map((p) => p.catch(() => null)));
    const gate: Record<string, string> = {
      'LeakCheck v2 (keyed)': 'T3MP3ST_LEAKCHECK_KEY',
      'DeHashed (keyed)': 'T3MP3ST_DEHASHED_KEY',
      'Snusbase (keyed)': 'T3MP3ST_SNUSBASE_KEY',
    };
    for (const rec of settled) {
      if (rec) deep.push(rec);
    }
    // Report key-gated lanes that did NOT run so the panel is explicit about coverage.
    for (const [service, envVar] of Object.entries(gate)) {
      const already = settled.some((s) => s && s.service === service);
      const applies = service !== 'DeHashed (keyed)' || kind !== 'phone';
      if (!already && applies) {
        deep.push({ service, status: 'key-required', note: `set ${envVar} in the server environment to unlock this dump lane` });
      }
    }
    for (const rec of settled) {
      if (!rec?.records) continue;
      for (const r of rec.records) {
        const secret = r.password || r.hash;
        if (!secret) continue;
        credentials.push({
          id: `cred_osint_${createHash('md5').update(`${rec.service}:${r.email || r.username || query}:${secret}`).digest('hex').slice(0, 12)}`,
          type: r.password ? 'password' : 'hash',
          username: r.username || r.email,
          secret,
          domain: r.email?.split('@')[1],
          source: `osint:${rec.service}${r.source ? ` (${r.source})` : ''}`,
          discoveredAt: Date.now(),
          notes: `dump-record for ${query} — provenance ${rec.service}`,
        });
      }
    }
  }

  return { query, kind, free, deep, credentials };
}

// =============================================================================
// PHONE INTEL — normalization, country routing, deep-link generation
// =============================================================================

const COUNTRY_PREFIXES: [string, string, number][] = [
  ['1', 'US/Canada (NANP)', 10], ['7', 'Russia/Kazakhstan', 10], ['20', 'Egypt', 10], ['27', 'South Africa', 9],
  ['30', 'Greece', 10], ['31', 'Netherlands', 9], ['32', 'Belgium', 9], ['33', 'France', 9], ['34', 'Spain', 9],
  ['36', 'Hungary', 9], ['39', 'Italy', 10], ['40', 'Romania', 9], ['41', 'Switzerland', 9], ['43', 'Austria', 10],
  ['44', 'United Kingdom', 10], ['45', 'Denmark', 8], ['46', 'Sweden', 9], ['47', 'Norway', 8], ['48', 'Poland', 9],
  ['49', 'Germany', 10], ['51', 'Peru', 9], ['52', 'Mexico', 10], ['53', 'Cuba', 8], ['54', 'Argentina', 10],
  ['55', 'Brazil', 11], ['56', 'Chile', 9], ['57', 'Colombia', 10], ['58', 'Venezuela', 10], ['60', 'Malaysia', 9],
  ['61', 'Australia', 9], ['62', 'Indonesia', 10], ['63', 'Philippines', 10], ['64', 'New Zealand', 9],
  ['65', 'Singapore', 8], ['66', 'Thailand', 9], ['81', 'Japan', 10], ['82', 'South Korea', 10],
  ['84', 'Vietnam', 9], ['86', 'China', 11], ['90', 'Turkey', 10], ['91', 'India', 10], ['92', 'Pakistan', 10],
  ['93', 'Afghanistan', 9], ['94', 'Sri Lanka', 9], ['95', 'Myanmar', 9], ['98', 'Iran', 10],
  ['211', 'South Sudan', 9], ['212', 'Morocco', 9], ['213', 'Algeria', 9], ['216', 'Tunisia', 8],
  ['218', 'Libya', 9], ['220', 'Gambia', 7], ['233', 'Ghana', 9], ['234', 'Nigeria', 10], ['250', 'Rwanda', 9],
  ['254', 'Kenya', 9], ['255', 'Tanzania', 9], ['256', 'Uganda', 9], ['260', 'Zambia', 9], ['263', 'Zimbabwe', 9],
  ['264', 'Namibia', 9], ['267', 'Botswana', 8], ['291', 'Eritrea', 7],
  ['350', 'Gibraltar', 8], ['351', 'Portugal', 9], ['352', 'Luxembourg', 9], ['353', 'Ireland', 9],
  ['355', 'Albania', 9], ['356', 'Malta', 8], ['357', 'Cyprus', 8], ['358', 'Finland', 9], ['359', 'Bulgaria', 9],
  ['370', 'Lithuania', 8], ['371', 'Latvia', 8], ['372', 'Estonia', 8], ['373', 'Moldova', 8],
  ['374', 'Armenia', 8], ['375', 'Belarus', 9], ['380', 'Ukraine', 9], ['381', 'Serbia', 9],
  ['385', 'Croatia', 9], ['386', 'Slovenia', 8], ['387', 'Bosnia', 8], ['389', 'North Macedonia', 8],
  ['420', 'Czechia', 9], ['421', 'Slovakia', 9], ['423', 'Liechtenstein', 7], ['501', 'Belize', 7],
  ['502', 'Guatemala', 8], ['503', 'El Salvador', 8], ['504', 'Honduras', 8], ['505', 'Nicaragua', 8],
  ['506', 'Costa Rica', 8], ['507', 'Panama', 8], ['509', 'Haiti', 8], ['590', 'Guadeloupe', 9],
  ['591', 'Bolivia', 8], ['592', 'Guyana', 7], ['593', 'Ecuador', 9], ['594', 'French Guiana', 9],
  ['595', 'Paraguay', 9], ['596', 'Martinique', 9], ['597', 'Suriname', 7], ['598', 'Uruguay', 8],
  ['670', 'East Timor', 8], ['672', 'Norfolk Island', 6], ['673', 'Brunei', 7], ['675', 'Papua New Guinea', 8],
  ['676', 'Tonga', 7], ['679', 'Fiji', 7], ['682', 'Cook Islands', 5], ['685', 'Samoa', 7],
  ['687', 'New Caledonia', 6], ['689', 'French Polynesia', 8], ['690', 'Tokelau', 5], ['691', 'Micronesia', 7],
  ['692', 'Marshall Islands', 7], ['850', 'North Korea', 10], ['852', 'Hong Kong', 8], ['853', 'Macau', 8],
  ['855', 'Cambodia', 9], ['856', 'Laos', 9], ['880', 'Bangladesh', 10], ['886', 'Taiwan', 9],
  ['960', 'Maldives', 7], ['961', 'Lebanon', 8], ['962', 'Jordan', 9], ['963', 'Syria', 9],
  ['964', 'Iraq', 10], ['965', 'Kuwait', 8], ['966', 'Saudi Arabia', 9], ['967', 'Yemen', 9],
  ['968', 'Oman', 8], ['970', 'Palestine', 9], ['971', 'UAE', 9], ['972', 'Israel', 9],
  ['973', 'Bahrain', 8], ['974', 'Qatar', 8], ['975', 'Bhutan', 8], ['976', 'Mongolia', 8],
  ['977', 'Nepal', 10], ['992', 'Tajikistan', 9], ['993', 'Turkmenistan', 8], ['994', 'Azerbaijan', 9],
  ['995', 'Georgia', 9], ['996', 'Kyrgyzstan', 9], ['998', 'Uzbekistan', 9],
];

export interface PhoneIntelResult {
  input: string;
  e164: string;
  digits: string;
  countryCode: string;
  country: string;
  expectedLength: number;
  lengthValid: boolean;
  nanp: { areaCode: string; exchange: string; validAreaCode: boolean } | null;
  searchLinks: { label: string; url: string }[];
}

export function phoneIntel(phoneRaw: string): PhoneIntelResult {
  const raw = phoneRaw.trim();
  const hadPlus = raw.startsWith('+') || raw.startsWith('00');
  const digits = raw.replace(/[^\d]/g, '').replace(/^00/, '');
  if (digits.length < 6 || digits.length > 15) throw new Error(`Invalid phone number: ${phoneRaw}`);

  // NANP: 10-digit numbers (no country code) are ambiguous — the operator should
  // confirm +1, but we report the US/Canada parse as the primary reading. The
  // assumed '1' has to be reflected in the E.164 form we emit.
  let cc: string | null = null;
  let country = 'unknown';
  let expected = 10;
  let national = digits;
  let e164 = `+${digits}`;

  if (hadPlus || digits.length > 10) {
    for (const len of [3, 2, 1]) {
      const prefix = digits.slice(0, len);
      const hit = COUNTRY_PREFIXES.find(([p]) => p === prefix);
      if (hit) { cc = hit[0]; country = hit[1]; expected = hit[2]; national = digits.slice(len); break; }
    }
    if (!cc) { country = `unknown (+${digits.slice(0, 2)}…)`; national = digits; }
  } else {
    cc = '1'; country = 'US/Canada (NANP, assumed — no country code given)'; expected = 10; national = digits;
    e164 = `+1${digits}`;
  }
  const nanp = cc === '1' && national.length === 10
    ? {
        areaCode: national.slice(0, 3),
        exchange: national.slice(3, 6),
        validAreaCode: !/^[01]/.test(national.slice(0, 3)) && national.slice(1, 3) !== '11',
      }
    : null;

  const bare = encodeURIComponent(digits);
  return {
    input: raw,
    e164,
    digits,
    countryCode: cc || '?',
    country,
    expectedLength: expected,
    lengthValid: national.length === expected,
    nanp,
    searchLinks: [
      { label: 'Google', url: `https://www.google.com/search?q=%22${bare}%22` },
      { label: 'Bing', url: `https://www.bing.com/search?q=%22${bare}%22` },
      { label: 'Yandex', url: `https://yandex.com/search/?text=%22${bare}%22` },
      { label: 'Truecaller', url: `https://www.truecaller.com/search/global/${digits}` },
      { label: 'Sync.me', url: `https://sync.me/search/?number=${digits}` },
      { label: 'WhatsApp check', url: `https://wa.me/${digits}` },
      { label: 'Telegram check', url: `https://t.me/+${digits}` },
      { label: 'Facebook search', url: `https://www.facebook.com/search/top?q=%22${bare}%22` },
      { label: 'LinkedIn posts', url: `https://www.linkedin.com/search/results/content/?keywords=%22${bare}%22` },
    ],
  };
}

// =============================================================================
// USERNAME PERMUTATION GENERATOR
// =============================================================================

export function usernamePermutations(
  first: string,
  last: string,
  extras: { middle?: string; birthYear?: string; keywords?: string[]; numbers?: boolean; max?: number } = {}
): string[] {
  const f = first.toLowerCase().replace(/[^a-z0-9]/g, '');
  const l = last.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!f || !l) throw new Error('Both first and last name are required');
  const m = (extras.middle || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const year = (extras.birthYear || '').replace(/\D/g, '').slice(-4);
  const base = new Set<string>();
  const add = (...parts: (string | undefined)[]) => {
    const joined = parts.filter(Boolean).join('');
    if (joined.length >= 3) base.add(joined);
  };

  add(f, l); add(l, f); add(f, '.', l); add(l, '.', f); add(f, '_', l); add(l, '_', f);
  add(f, '-', l); add(l, '-', f); add(f[0], l); add(f, l[0]); add(f[0], '.', l); add(f, '.', l[0]);
  if (m) { add(f, m[0], l); add(f, '.', m, '.', l); add(f, m, l); }
  for (const k of extras.keywords || []) {
    const kw = k.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!kw) continue;
    add(f, kw); add(kw, f); add(f, '.', kw); add(f, '_', kw); add(l, kw); add(kw, l);
  }

  const out = new Set<string>(base);
  if (extras.numbers !== false) {
    for (const b of base) {
      out.add(`${b}1`); out.add(`${b}123`); out.add(`${b}69`); out.add(`${b}007`);
      if (year) { out.add(`${b}${year}`); out.add(`${b}${year.slice(2)}`); }
    }
  }
  const max = extras.max && extras.max > 0 ? extras.max : 200;
  return [...out].sort((a, b) => a.length - b.length).slice(0, max);
}

// =============================================================================
// DORK GENERATORS — deep links the operator can fire in a browser
// =============================================================================

export interface DorkLink { label: string; url: string }

export function personDorks(params: { name?: string; email?: string; username?: string; phone?: string; domain?: string }): DorkLink[] {
  const links: DorkLink[] = [];
  const q = (s: string) => encodeURIComponent(s);
  const engines: [string, string][] = [
    ['Google', 'https://www.google.com/search?q='],
    ['Bing', 'https://www.bing.com/search?q='],
    ['DuckDuckGo', 'https://duckduckgo.com/?q='],
    ['Yandex', 'https://yandex.com/search/?text='],
    ['Brave', 'https://search.brave.com/search?q='],
  ];

  if (params.name) {
    for (const [label, base] of engines) links.push({ label: `${label}: name`, url: `${base}${q(`"${params.name}"`)}` });
    // Venmo public pages are only OSINT-accessible passively (search-engine index).
    // No Venmo endpoints are queried — account enumeration on a financial platform is out of scope.
    links.push({ label: 'Venmo: public pages (indexed)', url: `https://www.google.com/search?q=${q(`site:venmo.com "${params.name}"`)}` });
    links.push({ label: 'Google: name + CV/resume', url: `https://www.google.com/search?q=${q(`"${params.name}" (CV OR resume OR "curriculum vitae")`)}` });
    links.push({ label: 'Google: name + docs', url: `https://www.google.com/search?q=${q(`"${params.name}" (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls)`)}` });
    links.push({ label: 'LinkedIn people', url: `https://www.linkedin.com/search/results/people/?keywords=${q(params.name)}` });
    links.push({ label: 'Facebook', url: `https://www.facebook.com/public/${q(params.name)}` });
    links.push({ label: 'TruePeopleSearch', url: `https://www.truepeoplesearch.com/results?name=${q(params.name)}` });
    links.push({ label: 'FastPeopleSearch', url: `https://www.fastpeoplesearch.com/name/${q(params.name.replace(/\s+/g, '-'))}` });
    links.push({ label: 'Whitepages', url: `https://www.whitepages.com/name/${q(params.name.replace(/\s+/g, '-'))}` });
    links.push({ label: 'Spokeo', url: `https://www.spokeo.com/${q(params.name.replace(/\s+/g, '-'))}` });
    links.push({ label: "That'sThem", url: `https://thatsthem.com/name/${q(params.name.replace(/\s+/g, '-'))}` });
  }
  if (params.email) {
    for (const [label, base] of engines) links.push({ label: `${label}: email`, url: `${base}${q(`"${params.email}"`)}` });
    links.push({ label: 'GitHub commits (email → code)', url: `https://github.com/search?q=${q(params.email)}&type=code` });
    links.push({ label: 'Gravatar', url: `https://gravatar.com/${createHash('md5').update(params.email.toLowerCase()).digest('hex')}` });
    links.push({ label: 'Have I Been Pwned', url: `https://haveibeenpwned.com/account/${q(params.email)}` });
  }
  if (params.username) {
    const u = params.username.replace(/^@/, '');
    for (const [label, base] of engines) links.push({ label: `${label}: username`, url: `${base}${q(`"${u}"`)}` });
    links.push({ label: 'Venmo: profile (public page)', url: `https://venmo.com/u/${q(u)}` });
    links.push({ label: 'Venmo: indexed mentions', url: `https://www.google.com/search?q=${q(`site:venmo.com "${u}"`)}` });
    links.push({ label: 'Namechk (handle check)', url: `https://namechk.com/check/${q(u)}` });
    links.push({ label: 'KnowEm (aggregator)', url: `https://knowem.com/checkusernames.php?u=${q(u)}` });
    links.push({ label: 'InstantUsername', url: `https://instantusername.com/#/${q(u)}` });
    links.push({ label: 'WhatsMyName (web)', url: `https://whatsmyname.app/?q=${q(u)}` });
    links.push({ label: 'Reddit search', url: `https://www.reddit.com/search/?q=${q(u)}` });
  }
  if (params.phone) {
    const d = params.phone.replace(/\D/g, '');
    links.push({ label: 'Google: phone', url: `https://www.google.com/search?q=${q(`"${d}"`)}` });
    links.push({ label: 'Truecaller', url: `https://www.truecaller.com/search/global/${d}` });
    links.push({ label: 'Sync.me', url: `https://sync.me/search/?number=${d}` });
  }
  if (params.domain) {
    const dom = params.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    for (const [label, base] of engines) links.push({ label: `${label}: domain`, url: `${base}${q(`site:${dom}`)}` });
    links.push({ label: 'crt.sh (cert transparency)', url: `https://crt.sh/?q=${q(`%.${dom}`)}` },
    );
    links.push({ label: 'Wayback Machine', url: `https://web.archive.org/web/*/${dom}/*` });
    links.push({ label: 'URLScan', url: `https://urlscan.io/domain/${dom}` });
    links.push({ label: 'Shodan', url: `https://www.shodan.io/search?query=hostname%3A${q(dom)}` });
  }
  return links;
}

// =============================================================================
// PERSON LOCATOR — the composite dossier
// =============================================================================

export interface LocatorInput {
  subject?: string;
  name?: string;
  email?: string;
  username?: string;
  phone?: string;
  domain?: string;
  /** Parsed from a subject that was a URL. */
  url?: string;
}

export interface OsintDossier {
  subject: string;
  parsed: { email?: string; username?: string; phone?: string; domain?: string; url?: string };
  name?: string;
  socialAccounts: UsernameHit[];
  /** Profile-corroborated mismatches (a different person owns the handle) — excluded
   *  from results/presence and reported separately so they never pollute the dossier. */
  excludedAccounts: UsernameHit[];
  /** Contact core — the primary locator output. */
  emails: string[];
  phones: string[];
  addresses: string[];
  /** Demographics from dump records (keyed lanes). */
  ages: number[];
  dobs: string[];
  gravatar?: GravatarProfile;
  emailIntel?: EmailIntelResult;
  phone?: PhoneIntelResult;
  dumpLanes: DumpLaneResult[];
  photos: string[];
  locations: string[];
  /** City-level public location signals geocoded for the Geo Intel Map (OSINT layer). */
  geoPoints: GeoPoint[];
  /** Every source probed during the locate — found/absent/unknown audit trail. */
  sourcesChecked: { name: string; status: 'found' | 'absent' | 'unknown'; confidence: string; url?: string }[];
  /** Sanctions / watchlist / wanted-notice screening (name subjects). */
  screening?: ScreeningResult;
  /** Search-result mining runs (per query). */
  searchExtraction: { query: string; via: string; found: number }[];
  /** Public-records person records (browser-rendered page mining). */
  peopleRecords: PersonRecord[];
  /** Operator-ready markdown report (the DETAILED REPORT section). */
  report: string;
  identities: { source: string; detail: string }[];
  dorks: DorkLink[];
  presenceScore: number;
  ranAt: number;
  durationMs: number;
}

// =============================================================================
// GEO INTEL — IP geolocation + text geocoding (keyless public sources)
// =============================================================================
// Serves the Geo Intel Map: engagement-target IPs, egress/proxy exit, DFIR IOC
// infrastructure, and coarse OSINT location signals (city-level public data —
// Gravatar location text, NANP area regions). This is infrastructure geography,
// NOT a person-tracker: no GPS/device/telephony positioning is wired anywhere.

export interface GeoPoint {
  kind: 'egress' | 'target' | 'dfir' | 'osint';
  key: string;
  label: string;
  detail?: string;
  lat?: number;
  lon?: number;
  city?: string;
  region?: string;
  country?: string;
  org?: string;
  geoNote?: string;
}

export interface IpGeoResult {
  ip: string;
  resolved?: boolean;
  privateLan?: boolean;
  lat?: number;
  lon?: number;
  city?: string;
  region?: string;
  country?: string;
  org?: string;
  note?: string;
}

// RFC1918 + loopback + link-local + IETF documentation ranges (192.0.2/198.51.100/203.0.113)
// — the last three are fake-IP convention, never real geolocation targets.
const PRIVATE_IP_RE = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|::1|f[cd][0-9a-f]{2}:)/i;

export function isPrivateIp(host: string): boolean {
  return PRIVATE_IP_RE.test(host.trim());
}

interface IpwhoResponse {
  ip?: string; success?: boolean; message?: string;
  latitude?: number; longitude?: number;
  city?: string; region?: string; country?: string;
  connection?: { org?: string; isp?: string };
}

/** Keyless IP geolocation — ipwho.is (HTTPS, no key), ip-api.com as fallback. */
export async function ipGeo(ipRaw: string): Promise<IpGeoResult> {
  const ip = ipRaw.trim();
  if (isPrivateIp(ip) || ip === 'localhost') {
    return { ip, resolved: true, privateLan: true, note: 'private/loopback — no public geolocation (local LAN asset)' };
  }
  try {
    const j = await fetchJson<IpwhoResponse>(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (j && j.success !== false && typeof j.latitude === 'number' && typeof j.longitude === 'number') {
      return {
        ip,
        resolved: true,
        lat: j.latitude,
        lon: j.longitude,
        city: j.city,
        region: j.region,
        country: j.country,
        org: j.connection?.org || j.connection?.isp,
      };
    }
  } catch { /* fall through to the backup source */ }
  try {
    const fields = 'status,message,country,regionName,city,lat,lon,isp,query';
    const r = await osintFetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`);
    const j = (await r.json().catch(() => ({}))) as Record<string, unknown>;
    if (j.status === 'success' && typeof j.lat === 'number' && typeof j.lon === 'number') {
      return {
        ip, resolved: true,
        lat: j.lat as number, lon: j.lon as number,
        city: j.city as string, region: j.regionName as string, country: j.country as string,
        org: j.isp as string,
      };
    }
    return { ip, resolved: false, note: (j.message as string) || 'no geolocation returned' };
  } catch (error) {
    return { ip, resolved: false, note: `geolocation failed: ${error instanceof Error ? error.message.slice(0, 80) : 'network error'}` };
  }
}

export async function ipGeoMany(ips: string[]): Promise<IpGeoResult[]> {
  const unique = [...new Set(ips.map((i) => i.trim()).filter(Boolean))].slice(0, 25);
  const out: IpGeoResult[] = [];
  for (let i = 0; i < unique.length; i += 5) {
    out.push(...(await Promise.all(unique.slice(i, i + 5).map(ipGeo))));
  }
  return out;
}

/** Resolve hostnames to IPv4 before geolocating. */
export async function geoForHost(host: string): Promise<IpGeoResult & { host: string }> {
  const h = host.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h === 'localhost' || isPrivateIp(h)) {
    return { host: h, ...(await ipGeo(h)) };
  }
  try {
    const addr = (await dns.resolve4(h))[0];
    const geo = await ipGeo(addr);
    return { host: h, ...geo, ip: addr };
  } catch {
    return { host: h, ...(await ipGeo(h)), note: 'DNS resolution failed — attempted direct geolocation' };
  }
}

// --- text geocoding (Nominatim / OpenStreetMap — keyless, 1 req/s policy) ---

interface NominatimPlace { lat?: string; lon?: string; display_name?: string; type?: string }

const geocodeCache = new Map<string, { lat: number; lon: number; label: string } | null>();
const geocodeLastCall = { at: 0 };

/** Keyless text geocoding (city/place text → coordinates) via OpenStreetMap Nominatim.
 *  Throttled to 1 req/s and cached for the process lifetime per the usage policy. */
export async function geocodeText(query: string): Promise<{ lat: number; lon: number; label: string } | null> {
  const q = query.trim().slice(0, 200);
  if (!q) return null;
  if (geocodeCache.has(q)) return geocodeCache.get(q) ?? null;
  const wait = 1100 - (Date.now() - geocodeLastCall.at);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  geocodeLastCall.at = Date.now();
  try {
    const r = await osintFetch(
      `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(q)}&format=json&limit=1`,
      { headers: { 'user-agent': 'T3MP3ST-GeoIntel/1.0 (authorized security testing platform)' } }
    );
    const places = (await r.json().catch(() => [])) as NominatimPlace[];
    const hit = places[0]?.lat && places[0]?.lon
      ? { lat: parseFloat(places[0].lat!), lon: parseFloat(places[0].lon!), label: places[0].display_name || q }
      : null;
    geocodeCache.set(q, hit);
    return hit;
  } catch {
    return null;
  }
}

// =============================================================================
// DARK WEB DIRECT — onion search + leak-site monitoring (keyless public lanes)
// =============================================================================
// Two direct lanes instead of paid dump APIs:
//   1. Ransomware leak-site monitor — ransomware.live (keyless public aggregator of
//      the ransomware groups' own victim posts). Defender-oriented threat intel.
//   2. Onion search — Ahmia (public search engine indexing onion sites). Clearnet
//      path first; when a local Tor SOCKS daemon is running (9050 / Tor Browser
//      9150), queries Ahmia's own onion address and fetches .onion pages DIRECTLY
//      through the Tor circuit via curl --socks5-hostname.
// This searches/fetches PUBLIC dark-web content. It does not buy, download, or
// traffic in stolen-data dumps — record-level breach data stays behind the keyed
// lanes or the operator's own authorization.

import { execFile as execFileCb } from 'child_process';
import { promisify } from 'util';
import * as net from 'net';
const execFileP = promisify(execFileCb);

const AHMIA_ONION = 'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion';
const ONION_RE = /^https?:\/\/[a-z2-7]{16,56}\.onion(\/|$)/i;

export interface TorStatus {
  available: boolean;
  port?: number;
  source?: 'tor-daemon' | 'tor-browser';
  note: string;
}

let torStatusCache: { at: number; status: TorStatus } | null = null;

/** Detect a local Tor SOCKS daemon (9050) or Tor Browser (9150). Cached 60s. */
export async function torStatus(force = false): Promise<TorStatus> {
  if (!force && torStatusCache && Date.now() - torStatusCache.at < 60_000) return torStatusCache.status;
  const probe = (port: number) => new Promise<boolean>((resolve) => {
    const sock = net.connect({ port, host: '127.0.0.1', timeout: 800 });
    sock.once('connect', () => { sock.destroy(); resolve(true); });
    sock.once('timeout', () => { sock.destroy(); resolve(false); });
    sock.once('error', () => resolve(false));
  });
  let status: TorStatus;
  if (await probe(9050)) status = { available: true, port: 9050, source: 'tor-daemon', note: 'Tor SOCKS live on 127.0.0.1:9050 — direct .onion access armed' };
  else if (await probe(9150)) status = { available: true, port: 9150, source: 'tor-browser', note: 'Tor Browser SOCKS live on 127.0.0.1:9150 — direct .onion access armed' };
  else status = { available: false, note: 'no local Tor on 9050/9150 — start Tor (daemon or Tor Browser) to fetch .onion pages directly; search still works over clearnet where reachable' };
  torStatusCache = { at: Date.now(), status };
  return status;
}

/** Fetch a page through the local Tor circuit (curl --socks5-hostname — remote DNS,
 *  the .onion resolution happens inside Tor). Requires torStatus().available. */
export async function onionFetch(urlRaw: string, maxBytes = 400_000): Promise<{ url: string; status: number; body: string }> {
  const url = urlRaw.trim();
  if (!ONION_RE.test(url)) throw new Error('not a .onion URL — onion fetch only handles hidden services');
  const tor = await torStatus();
  if (!tor.available) throw new Error(tor.note);
  let stdout = '';
  try {
    const out = await execFileP(
      'curl',
      ['--socks5-hostname', `127.0.0.1:${tor.port}`, '-sL', '--max-time', '30', '-A', UA, '-w', '\\n__T3MP3ST_STATUS__%{http_code}', url],
      { timeout: 35_000, maxBuffer: 16 * 1024 * 1024 }
    );
    stdout = out.stdout;
  } catch (e) {
    const err = e as { code?: number | string; stderr?: string; killed?: boolean };
    if (err.killed) throw new Error(`onion fetch timed out through the Tor circuit: ${url}`);
    const tail = (err.stderr || '').trim().slice(-120);
    throw new Error(`onion fetch failed (curl exit ${err.code ?? '?'}) — hidden service down, stale address, or circuit congestion${tail ? `: ${tail}` : ''}`);
  }
  const marker = stdout.lastIndexOf('__T3MP3ST_STATUS__');
  const body = (marker >= 0 ? stdout.slice(0, marker) : stdout).slice(0, maxBytes);
  const status = marker >= 0 ? parseInt(stdout.slice(marker + 18).trim(), 10) || 0 : 0;
  return { url, status, body };
}

export interface OnionResult { title: string; url: string; snippet: string }

/** Parse Ahmia result HTML (tolerant — result blocks are <li class="result"> with an
 *  onion anchor, optional <p> snippet and <cite> URL). Exported for unit tests. */
export function parseAhmiaResults(html: string, max = 25): OnionResult[] {
  const results: OnionResult[] = [];
  const seen = new Set<string>();
  const blocks = html.split(/<li[^>]*class="[^"]*result[^"]*"/i).slice(1);
  for (const block of blocks) {
    const anchor = block.match(/<a[^>]+href="(https?:\/\/[a-z2-7]{16,56}\.onion[^"]*)"[^>]*>([\s\S]*?)<\/a>/i);
    if (!anchor) continue;
    const url = anchor[1].replace(/&amp;/g, '&');
    if (seen.has(url)) continue;
    const title = anchor[2].replace(/<[^>]+>/g, '').trim().slice(0, 160) || url;
    const snippetMatch = block.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
    const snippet = snippetMatch ? snippetMatch[1].replace(/<[^>]+>/g, '').trim().slice(0, 300) : '';
    seen.add(url);
    results.push({ title, url, snippet });
    if (results.length >= max) break;
  }
  return results;
}

export interface AhmiaSearchResult {
  query: string;
  via: 'tor' | 'clearnet';
  results: OnionResult[];
  note?: string;
}

/** Onion search via Ahmia. Prefers the Tor circuit (Ahmia's own onion address —
 *  immune to clearnet exit blocking); falls back to clearnet ahmia.fi and reports
 *  honestly when the exit is redirected away (exit-IP reputation). */
export async function ahmiaSearch(queryRaw: string): Promise<AhmiaSearchResult> {
  const query = queryRaw.trim().slice(0, 200);
  if (!query) throw new Error('query required');
  const tor = await torStatus();
  if (tor.available) {
    try {
      const page = await onionFetch(`${AHMIA_ONION}/search/?q=${encodeURIComponent(query)}`);
      const results = parseAhmiaResults(page.body);
      return { query, via: 'tor', results, note: results.length ? undefined : 'search executed over Tor — no results parsed for this query' };
    } catch (e) {
      // fall through to clearnet with the Tor failure noted
      const clear = await ahmiaClearnet(query).catch(() => null);
      if (clear) return { ...clear, note: `Tor fetch failed (${String(e).slice(0, 80)}); clearnet fallback used` };
      throw e;
    }
  }
  return ahmiaClearnet(query);
}

async function ahmiaClearnet(query: string): Promise<AhmiaSearchResult> {
  try {
    const res = await osintFetch(`https://ahmia.fi/search/?q=${encodeURIComponent(query)}`, { redirect: 'manual' });
    if (res.status >= 300 && res.status < 400) {
      return {
        query, via: 'clearnet', results: [],
        note: `ahmia.fi redirected this proxy exit away from search (HTTP ${res.status}) — exit-IP reputation. Start a local Tor daemon (port 9050) and the same search runs DIRECT over the Tor circuit.`,
      };
    }
    const html = await res.text();
    const results = parseAhmiaResults(html);
    return { query, via: 'clearnet', results };
  } catch (error) {
    throw new Error(`Ahmia clearnet search failed: ${error instanceof Error ? error.message.slice(0, 100) : 'network error'}`);
  }
}

// --- ransomware leak-site monitor (ransomware.live — keyless public API) ---

export interface LeakVictim {
  victim: string;
  domain?: string;
  group: string;
  country?: string;
  activity?: string;
  attackDate?: string;
  discovered?: string;
  postUrl?: string;
  description?: string;
}

interface RwVictimRecord {
  victim?: string; domain?: string; group?: string; country?: string; activity?: string;
  attackdate?: string; discovered?: string; url?: string; claim_url?: string; description?: string;
}

function toLeakVictim(r: RwVictimRecord): LeakVictim {
  return {
    victim: r.victim || '(unnamed)',
    domain: r.domain || undefined,
    group: r.group || 'unknown',
    country: r.country || undefined,
    activity: r.activity || undefined,
    attackDate: r.attackdate || undefined,
    discovered: r.discovered || undefined,
    postUrl: r.url || r.claim_url || undefined,
    description: (r.description || '').replace(/\s+/g, ' ').slice(0, 240) || undefined,
  };
}

export interface LeakMonitorResult {
  keyword: string;
  found: number;
  searched: 'api-index' | 'recent-scan';
  victims: LeakVictim[];
  note?: string;
}

/** Check ransomware leak sites for a keyword (target domain, company name, …).
 *  Uses the ransomware.live search API, falls back to a local filter over the
 *  recent-victims feed. This is the free alternative to paid dark-web monitoring. */
export async function ransomwareLeakSearch(keywordRaw: string): Promise<LeakMonitorResult> {
  const keyword = keywordRaw.trim().toLowerCase().slice(0, 120);
  if (!keyword) throw new Error('keyword required (target domain or company name)');
  const kw = keyword.replace(/^https?:\/\//, '').replace(/^www\./, '');

  const search = await fetchJson<RwVictimRecord[]>(`https://api.ransomware.live/v2/searchvictims/${encodeURIComponent(kw)}`);
  if (search && Array.isArray(search)) {
    const victims = search.slice(0, 40).map(toLeakVictim);
    return { keyword: kw, found: victims.length, searched: 'api-index', victims };
  }

  const recent = await fetchJson<RwVictimRecord[]>('https://api.ransomware.live/v2/recentvictims');
  const feed = Array.isArray(recent) ? recent : [];
  const victims = feed
    .filter((r) => `${r.victim || ''} ${r.domain || ''} ${r.group || ''}`.toLowerCase().includes(kw))
    .slice(0, 40)
    .map(toLeakVictim);
  return {
    keyword: kw, found: victims.length, searched: 'recent-scan', victims,
    note: 'keyword index unreachable — scanned the latest victim feed only',
  };
}

function parseSubject(subject: string, input: LocatorInput): LocatorInput {
  const s = subject.trim();
  const out: LocatorInput = { ...input };
  if (EMAIL_RE.test(s)) out.email = s.toLowerCase();
  else if (/^https?:\/\//i.test(s)) {
    out.url = s;
    try {
      const u = new URL(s);
      out.domain = u.hostname.replace(/^www\./, '');
      const seg = u.pathname.split('/').filter(Boolean);
      if (seg.length) {
        // Profile URLs: github.com/USER, reddit.com/user/USER, x.com/@USER, t.me/USER ...
        const raw = seg[0] === 'user' || seg[0] === 'users' ? seg[1] : seg[0];
        const handle = raw?.startsWith('@') ? raw.slice(1) : raw;
        if (handle && !/^(api|blog|help|about|login|signup|settings|notifications|messages|search|explore)$/i.test(handle)) {
          out.username = decodeURIComponent(handle);
        }
      }
    } catch { /* malformed URL — domain stays unset */ }
  } else if (/^[\w.-]+\.[a-z]{2,}$/i.test(s)) out.domain = s.toLowerCase();
  else if (/^\+?\d[\d\s().-]{6,}$/.test(s)) out.phone = s;
  else if (s.includes('@') && s.length > 1) out.username = s.replace(/^@/, '');
  else if (!s.includes(' ')) out.username = s;
  else out.name = s;
  return out;
}

/** Operator-ready markdown report for a dossier — the DETAILED REPORT section:
 *  identifiers, every found record with its source, breach exposure, identity and
 *  location signals, the full sources-consulted audit, and honest next steps. */
export function buildDossierReport(d: OsintDossier): string {
  const L: string[] = [];
  L.push(`# OSINT DOSSIER — ${d.subject}`);
  L.push('');
  L.push(`Generated ${new Date(d.ranAt).toISOString()} · presence ${d.presenceScore}/100 · runtime ${(d.durationMs / 1000).toFixed(1)}s`);
  L.push('');
  L.push('## 1. IDENTIFIERS');
  const ids = Object.entries(d.parsed).filter(([, v]) => v);
  if (d.name) ids.push(['name', d.name]);
  if (ids.length === 0) L.push('- none detected in the subject string');
  for (const [k, v] of ids) L.push(`- **${k}:** ${v}`);
  // Subject assessment — corroboration up front, not buried in a list.
  const matched = d.socialAccounts.filter((h) => h.identity === 'name-match');
  const mismatched = d.excludedAccounts || [];
  if (d.name || d.socialAccounts.length > 0) {
    L.push('');
    if (matched.length > 0) {
      const strongest = matched[0];
      L.push(`- **assessment:** ${matched.length} account(s) corroborate the subject's name — strongest signal: ${strongest.site} ("${strongest.profile?.displayName || 'name match'}"). ${mismatched.length} handle(s) belonged to different people and were EXCLUDED from these results.`);
    } else if (d.socialAccounts.length > 0) {
      L.push(`- **assessment:** ${d.socialAccounts.length} handle(s) claimed but NONE corroborated against a name — treat every hit as unverified (same handle ≠ same person).`);
    } else {
      L.push('- **assessment:** no corroborated accounts found');
    }
  }
  L.push('');

  L.push(`## 2. CONTACT — EMAILS · PHONES · ADDRESSES`);
  if (d.emails.length > 0) {
    L.push(`- **emails (${d.emails.length}):**`);
    for (const e of d.emails) L.push(`  - ${e}`);
  } else {
    L.push('- **emails:** none recovered — arm the dump-lane keys (DeHashed/LeakCheck v2) or check the public-records workbench');
  }
  if (d.phones.length > 0) {
    L.push(`- **phones (${d.phones.length}):**`);
    for (const p of d.phones) L.push(`  - ${p}`);
  } else {
    L.push('- **phones:** none recovered — same levers (keyed dump records carry phone fields; public-records links below)');
  }
  if (d.addresses.length > 0) {
    L.push(`- **addresses (${d.addresses.length}):**`);
    for (const a of d.addresses) L.push(`  - ${a}`);
  } else {
    L.push('- **addresses:** none in keyed dump records — address history lives in the public-records workbench (browser) and keyed dump records');
  }
  L.push('');

  L.push(`## 3. SOCIAL FOOTPRINT — ${d.socialAccounts.length} account(s) for this subject (swept from the contact/identifier results above)`);
  if (d.socialAccounts.length === 0) L.push('- no public profiles found for the handles swept');
  for (const h of d.socialAccounts) {
    const ident = h.identity === 'name-match' ? '✓ IDENTITY MATCH' : 'handle-only';
    const contacts = [h.profile?.email, h.profile?.blog, h.profile?.twitter, h.profile?.location].filter(Boolean).join(' · ');
    L.push(`- [${h.confidence}] **${h.site}** — ${h.url}${h.profile?.displayName ? ` — "${h.profile.displayName}"` : ''} _(${ident})_${contacts ? `\n  - contact/location: ${contacts}` : ''}`);
  }
  if (mismatched.length > 0) {
    L.push('');
    L.push(`### EXCLUDED — different people (${mismatched.length}, not part of this dossier)`);
    for (const h of mismatched) L.push(`- ${h.site}: ${h.url}${h.profile?.displayName ? ` — owned by "${h.profile.displayName}"` : ''}`);
  }
  L.push('');

  L.push('## 4. BREACH / DUMP EXPOSURE');
  let breach = false;
  for (const lane of d.dumpLanes) {
    for (const f of lane.free) {
      L.push(`- ${lane.kind} \`${lane.query}\` — **${f.service}**: ${f.found === 'unknown' ? 'unknown' : `${f.found} record(s)`}${f.sources?.length ? ` — sources: ${f.sources.slice(0, 6).join('; ')}` : ''}${f.note ? ` — _${f.note}_` : ''}`);
      breach = true;
    }
    for (const dep of lane.deep) {
      if ('status' in dep) L.push(`- ${lane.kind} \`${lane.query}\` — ${dep.service}: **not run** — ${dep.note}`);
      else {
        L.push(`- ${lane.kind} \`${lane.query}\` — ${dep.service}: **${dep.found} record(s)**`);
        for (const r of (dep.records || []).slice(0, 10)) {
          L.push(`  - ${r.email || r.username || '?'}${r.password ? ` — password material recovered (${r.source || 'unknown dump'})` : r.hash ? ` — hash recovered (${r.source || 'unknown dump'})` : ''}`);
        }
      }
      breach = true;
    }
    if (lane.credentials.length > 0) L.push(`- ${lane.kind} \`${lane.query}\` — **${lane.credentials.length} credential(s) forwarded to the Evidence Vault**`);
  }
  if (!breach) L.push('- no breach lanes ran for this subject (no email/username/phone identifier present)');
  L.push('');

  L.push('## 5. IDENTITY SIGNALS');
  let ident = false;
  if (d.emailIntel?.gravatar?.exists) {
    const g = d.emailIntel.gravatar;
    L.push(`- Gravatar: **${g.displayName || '(no display name)'}**${g.location ? ` @ ${g.location}` : ''}${g.accounts?.length ? ` — linked accounts: ${g.accounts.map((a) => a.shortname).join(', ')}` : ''}`);
    ident = true;
  }
  for (const i of d.identities) {
    L.push(`- ${i.source}: ${i.detail}`);
    ident = true;
  }
  if (!ident) L.push('- none');
  L.push('');

  L.push('## 6. LOCATION SIGNALS (city-level, public data only)');
  if (d.locations.length === 0) L.push('- none');
  for (const loc of d.locations) L.push(`- ${loc}`);
  L.push('');

  if (d.screening) {
    L.push(`## 6b. SANCTIONS / WATCHLIST SCREENING — ${d.screening.name}`);
    for (const s of d.screening.sources) {
      if (s.status === 'ok' && s.matches.length > 0) {
        L.push(`- **${s.source}: ${s.matches.length} MATCH(ES)**${s.via ? ` (via ${s.via})` : ''}`);
        for (const m of s.matches.slice(0, 10)) L.push(`  - ${m.name} — ${m.detail}`);
      } else if (s.status === 'ok') {
        L.push(`- ${s.source}: no matches${s.via ? ` (via ${s.via})` : ''}`);
      } else {
        L.push(`- ${s.source}: ${s.status.toUpperCase()} — ${s.note || ''}`);
      }
    }
    L.push('');
  }

  const found = d.sourcesChecked.filter((s) => s.status === 'found');
  const absent = d.sourcesChecked.filter((s) => s.status === 'absent');
  const unknownS = d.sourcesChecked.filter((s) => s.status === 'unknown');
  L.push(`## 7. SOURCES CONSULTED — ${d.sourcesChecked.length} platform probe(s)`);
  L.push(`- **found (${found.length}):** ${found.map((s) => s.name).join(', ') || '—'}`);
  L.push(`- **checked, no profile (${absent.length}):** ${absent.length > 0 ? absent.map((s) => s.name).join(', ') : '—'}`);
  L.push(`- **unknown — blocked or rate-limited (${unknownS.length}):** ${unknownS.map((s) => s.name).join(', ') || '—'}`);
  L.push('- breach lanes consulted: LeakCheck public, XposedOrNot, HIBP Pwned Passwords (+ LeakCheck v2 / DeHashed / Snusbase when operator keys are configured)');
  L.push('');

  if (d.name) {
    const personName = d.name;
    const slug = personName.replace(/\s+/g, '-');
    const sp = personName.replace(/\s+/g, '+');
    L.push(`## 7b. PUBLIC RECORDS WORKBENCH — ${personName}`);
    L.push('These hold legal public-record data (address history, age/DOB range, relatives, phones). They WAF-block server-side access — open them in YOUR browser:');
    L.push(`- TruePeopleSearch: https://www.truepeoplesearch.com/results?name=${sp}`);
    L.push(`- FastPeopleSearch: https://www.fastpeoplesearch.com/name/${slug}`);
    L.push(`- Whitepages: https://www.whitepages.com/name/${slug}`);
    L.push(`- That'sThem: https://thatsthem.com/name/${slug}`);
    L.push(`- Spokeo: https://www.spokeo.com/${slug}`);
    L.push(`- LinkedIn (professional footprint): https://www.linkedin.com/search/results/people/?keywords=${sp}`);
    L.push(`- Voter/property/court records: search your state's voter file + county property appraiser + PACER (federal) for "${personName}"`);
    L.push('- Identity-record fields (DOB, address history) ALSO surface in the dump lanes above when their source dumps contained them and the operator key is armed — that is the licensed route to record-level data.');
    L.push('- There is NO legal keyless source for SSN-level identity data, and stolen "fullz" dumps are off-limits. This dossier stops at what public + licensed sources return.');
    L.push('');
  }

  L.push('## 8. RECOMMENDED NEXT STEPS');
  const steps: string[] = [];
  if (d.socialAccounts.length > 0) steps.push('Review the highest-confidence profiles first; screenshots + archive before engaging.');
  if (d.photos.length > 0) steps.push('Reverse-image search the recovered avatar(s) for cross-platform matches.');
  if (d.dumpLanes.some((l) => l.free.some((f) => typeof f.found === 'number' && f.found > 0))) steps.push('Breach exposure confirmed — configure dump-lane keys (T3MP3ST_LEAKCHECK_KEY / DEHASHED / SNUSBASE) for record-level detail, then pursue ONLY within your authorization.');
  if (d.sourcesChecked.some((s) => s.status === 'unknown')) steps.push('Some platforms returned unknown (login-wall / rate-limit) — re-run through residential egress or check manually.');
  if (d.phone) steps.push(`Phone ${d.phone.e164}: fire the Truecaller/Sync.me deep-links for carrier and reverse-lookup data.`);
  steps.push('Hand the dossier handles to a recon operator (tools: osint_username_sweep, osint_breach_lookup) for continuous monitoring.');
  if (d.screening) steps.push('Screening sources marked BLOCKED resist datacenter/Tor egress — check them from your own browser (links in PUBLIC RECORDS / dorks), or arm a residential exit and re-run.');
  for (const s of steps) L.push(`- ${s}`);
  L.push('');
  L.push('_Public-source OSINT only. City-level geography. No device positioning, no intrusion — engage recovered credentials strictly within your authorization._');
  return L.join('\n');
}

/**
 * The full human-lookup chain: parse the subject, sweep socials, pull Gravatar
 * identity + linked accounts, run breach/dump lanes on every identifier, resolve
 * phone country, and generate operator deep-links. All keyless unless the operator
 * configured dump-lane keys.
 */
export async function locatePerson(input: LocatorInput): Promise<OsintDossier> {
  const started = Date.now();
  const parsedInput = input.subject ? parseSubject(input.subject, input) : input;
  const { email, phone, domain } = parsedInput;
  let username = parsedInput.username ? validateUsername(parsedInput.username) : null;
  if (!username && email) username = validateUsername(email.split('@')[0]) || null;

  const socialAccounts: UsernameHit[] = [];
  const dumpLanes: DumpLaneResult[] = [];
  const emails: string[] = email ? [email.toLowerCase()] : [];
  const phones: string[] = phone ? [phone.trim()] : [];
  const addresses: string[] = [];
  const ages: number[] = [];
  const dobs: string[] = [];
  const photos: string[] = [];
  const locations: string[] = [];
  const identities: { source: string; detail: string }[] = [];
  const sourcesChecked: OsintDossier['sourcesChecked'] = [];
  const srcRank = { found: 3, unknown: 2, absent: 1 } as const;
  const mergeChecked = (details: UsernameHit[], tag?: string): void => {
    for (const d of details) {
      const name = tag ? `${d.site} [${tag}]` : d.site;
      const entry = { name, status: d.status, confidence: d.confidence, url: d.url };
      const existing = sourcesChecked.find((s) => s.name === name);
      if (!existing) sourcesChecked.push(entry);
      else if (srcRank[d.status] > srcRank[existing.status]) sourcesChecked[sourcesChecked.indexOf(existing)] = entry;
    }
  };

  // Assembled up front so the parallel jobs below can fill it in — the phone lane
  // awaits inline, which means the .then() callbacks of other jobs can fire before
  // this function reaches any later declaration.
  const dossier: OsintDossier = {
    subject: input.subject || username || email || phone || domain || input.name || '(no subject)',
    parsed: { email, username: username || undefined, phone, domain },
    name: parsedInput.name,
    socialAccounts: [],
    excludedAccounts: [],
    dumpLanes,
    emails,
    phones,
    addresses,
    ages,
    dobs,
    photos,
    locations,
    geoPoints: [],
    sourcesChecked,
    searchExtraction: [],
    peopleRecords: [],
    report: '',
    identities,
    dorks: [],
    presenceScore: 0,
    ranAt: Date.now(),
    durationMs: 0,
  };

  // ─────────────────────────────────────────────────────────────────
  // WAVE 1 — IDENTITY CORE: contact data first (emails, phones, addresses,
  // breach/dump exposure, screening). Socials are deliberately LAST and
  // derive from whatever wave 1 confirms.
  // ─────────────────────────────────────────────────────────────────
  const jobs: Promise<void>[] = [];

  if (email) {
    jobs.push(
      emailIntel(email).then((intel) => {
        dossier.gravatar = intel.gravatar;
        dossier.emailIntel = intel;
        if (intel.gravatar.exists) {
          photos.push(intel.gravatar.avatarUrl);
          if (intel.gravatar.displayName) identities.push({ source: 'Gravatar', detail: `display name: ${intel.gravatar.displayName}` });
          if (intel.gravatar.location) locations.push(intel.gravatar.location);
        }
      }).catch(() => undefined)
    );
    jobs.push(dumpDatabaseLookup(email, 'email').then((r) => { dumpLanes.push(r); }).catch(() => undefined));
  }
  if (phone) {
    jobs.push(
      (async () => {
        try {
          const pi = phoneIntel(phone);
          dossier.phone = pi;
          if (pi.nanp && pi.nanp.validAreaCode) locations.push(`NANP area code ${pi.nanp.areaCode} (region lookup: npa ${pi.nanp.areaCode})`);
          dumpLanes.push(await dumpDatabaseLookup(pi.e164, 'phone').catch(() => ({ query: pi.e164, kind: 'phone' as const, free: [], deep: [], credentials: [] })));
        } catch { /* invalid phone — skip */ }
      })()
    );
  }
  if (username) {
    jobs.push(
      dumpDatabaseLookup(username, 'username').then((r) => { dumpLanes.push(r); }).catch(() => undefined)
    );
  }
  if (domain) {
    jobs.push(
      dns.resolveMx(domain).then((mx) => {
        if (mx.length) identities.push({ source: `MX ${domain}`, detail: `mail handled by ${mx.map((m) => m.exchange).join(', ')}` });
      }).catch(() => undefined)
    );
  }
  if (parsedInput.name && parsedInput.name.includes(' ')) {
    jobs.push(
      screenSubject(parsedInput.name).then((screening) => {
        dossier.screening = screening;
      }).catch(() => undefined)
    );
  }
  if (parsedInput.name && parsedInput.name.includes(' ')) {
    jobs.push(
      peopleRecordSearch(parsedInput.name).then((result) => {
        dossier.peopleRecords = result.records;
        for (const rec of result.records) {
          if (rec.age && !ages.includes(rec.age)) ages.push(rec.age);
          if (rec.city && !locations.some((l) => l.includes(rec.city!))) locations.push(rec.city + ' (public records)');
          for (const a of rec.pastAddresses.slice(0, 4)) {
            const key = a.toLowerCase();
            if (!addresses.some((x) => x.toLowerCase().includes(key))) addresses.push(a + ' (public records)');
          }
          for (const aka of rec.akas.slice(0, 4)) {
            identities.push({ source: 'public records AKA', detail: aka });
          }
        }
      }).catch((e) => {
        identities.push({ source: 'public records', detail: 'lookup failed: ' + String(e).slice(0, 120) });
      })
    );
  }

  await Promise.all(jobs);

  // Wave 1 harvest: dump records carry the subject's other identifiers — other email
  // addresses, phone numbers, street addresses, and usernames. These are the locator's
  // primary output and drive wave 2.
  const derivedHandles: { handle: string; source: string }[] = [];
  for (const lane of dumpLanes) {
    for (const dep of lane.deep) {
      if ('status' in dep) continue;
      for (const r of dep.records || []) {
        if (r.email && !emails.includes(r.email.toLowerCase())) {
          emails.push(r.email.toLowerCase());
          identities.push({ source: dep.service, detail: `email in dump records: ${r.email.toLowerCase()}` });
        }
        if (r.phone && !phones.includes(r.phone)) {
          phones.push(r.phone);
          identities.push({ source: dep.service, detail: `phone in dump records: ${r.phone}` });
        }
        const addr = [r.address, r.city, r.state, r.country].filter(Boolean).join(', ');
        if (r.address && !addresses.some((a) => a.includes(r.address!))) {
          addresses.push(addr);
          identities.push({ source: dep.service, detail: `address in dump records: ${addr}` });
        }
        if (r.dob && !dobs.includes(r.dob)) dobs.push(r.dob);
        if (r.age) { const a = parseInt(r.age, 10); if (!isNaN(a) && !ages.includes(a)) ages.push(a); }
        const u = validateUsername(r.username || '');
        if (u && !derivedHandles.some((c) => c.handle === u)) derivedHandles.push({ handle: u, source: dep.service });
      }
    }
  }

  // Wave 1.5 — search extraction: mine engine results for contact data.
  const searchQueries: { q: string; kind: string }[] = [];
  if (parsedInput.name) searchQueries.push({ q: `"${parsedInput.name}"`, kind: 'name' });
  if (email) searchQueries.push({ q: `"${email}"`, kind: 'email' });
  if (phone) searchQueries.push({ q: `"${phone}"`, kind: 'phone' });
  for (const { q, kind } of searchQueries.slice(0, 3)) {
    const extraction = await searchExtract(q).catch(() => null);
    if (!extraction) continue;
    dossier.searchExtraction.push({ query: q, via: extraction.via, found: extraction.results.length });
    for (const e of extraction.extracted.emails) {
      if (!emails.includes(e)) {
        emails.push(e);
        identities.push({ source: `search:${kind}`, detail: `email mined from search results: ${e}` });
      }
    }
    for (const p of extraction.extracted.phones) {
      if (!phones.includes(p)) {
        phones.push(p);
        identities.push({ source: `search:${kind}`, detail: `phone mined from search results: ${p}` });
      }
    }
    for (const sUrl of extraction.extracted.socialUrls) {
      const handleMatch = sUrl.match(/(?:github\.com|t\.me)\/([A-Za-z0-9_-]+)/);
      const u = handleMatch ? validateUsername(handleMatch[1]) : null;
      if (u && !derivedHandles.some((c) => c.handle === u)) derivedHandles.push({ handle: u, source: `search (${kind})` });
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // WAVE 2 — SOCIAL FOOTPRINT, derived from the identity core. Handle
  // priority: explicit subject handle → email local-part → dump-record
  // usernames → Gravatar linked usernames → name permutations (last).
  // ─────────────────────────────────────────────────────────────────
  const candidates: { handle: string; source: string; primary: boolean }[] = [];
  if (username) candidates.push({ handle: username, source: 'subject handle', primary: true });
  if (email && email.split('@')[0] !== username) {
    const lp = validateUsername(email.split('@')[0]);
    if (lp) candidates.push({ handle: lp, source: 'email local-part', primary: false });
  }
  for (const dh of derivedHandles) {
    if (!candidates.some((c) => c.handle.toLowerCase() === dh.handle.toLowerCase())) {
      candidates.push({ handle: dh.handle, source: dh.source, primary: false });
    }
  }
  for (const acct of dossier.gravatar?.accounts || []) {
    const u = validateUsername(acct.username || '');
    if (u && !candidates.some((c) => c.handle.toLowerCase() === u.toLowerCase())) {
      candidates.push({ handle: u, source: 'Gravatar linked account', primary: false });
    }
  }
  const primaryCandidates = candidates.slice(0, 4);

  if (primaryCandidates.length > 0) {
    for (const cand of primaryCandidates) {
      const sweep = await runUsernameSweep(cand.handle, { hints: { name: parsedInput.name } }).catch(() => null);
      if (!sweep) continue;
      const tag = cand.primary ? undefined : cand.handle;
      mergeChecked(sweep.details, tag);
      for (const hit of sweep.found) {
        const tagged: UsernameHit = tag ? { ...hit, site: `${hit.site} [${tag}]` } : hit;
        socialAccounts.push(tagged);
        identities.push({
          source: `${hit.site} (via ${cand.source})`,
          detail: `handle "${cand.handle}" claimed: ${hit.url}${hit.identity === 'name-match' ? ` — corroborated: "${hit.profile?.displayName || 'name match'}"` : ''}`,
        });
      }
      // A corroborated match on a derived handle confirms the handle chain.
      if (sweep.found.some((h) => h.identity === 'name-match')) {
        identities.push({ source: 'corroboration', detail: `handle "${cand.handle}" (${cand.source}) corroborated as the subject — accounts above are the same person` });
      }
    }
  } else if (parsedInput.name && !email && !phone && !domain) {
    // Name-only subject: hunt handle variants of the real name across the
    // high-reliability subset of the catalog (the whole point of a name lookup).
    const words = (parsedInput.name || '').trim().split(/\s+/).filter(Boolean);
    if (words.length >= 2) {
      let perms: string[] = [];
      try {
        perms = usernamePermutations(words[0], words[words.length - 1], { max: 12 });
      } catch { /* no perms */ }
      for (let i = 0; i < perms.length; i += 3) {
        const chunk = perms.slice(i, i + 3);
        const sweeps = await Promise.all(
          chunk.map((perm) => runUsernameSweep(perm, { limit: 20, hints: { name: parsedInput.name } }).catch(() => null))
        );
        for (const sweep of sweeps) {
          if (!sweep) continue;
          mergeChecked(sweep.details, sweep.username);
          for (const hit of sweep.found) {
            socialAccounts.push({ ...hit, site: `${hit.site} [${sweep.username}]` });
            identities.push({ source: hit.site, detail: `handle "${sweep.username}" (from name) claimed: ${hit.url}` });
          }
        }
      }
    }
  }

  // Dedupe accounts (perm/secondary sweeps can double-hit), then SPLIT: corroborated
  // mismatches (a different person owns the handle) are excluded from the dossier's
  // results entirely — they get their own disclosure section, never mixed into hits.
  const seenUrls = new Set<string>();
  const uniqueAccounts = socialAccounts.filter((h) => (seenUrls.has(h.url) ? false : (seenUrls.add(h.url), true)));
  const excluded = uniqueAccounts.filter((h) => h.identity === 'name-mismatch');
  const kept = uniqueAccounts.filter((h) => h.identity !== 'name-mismatch');
  dossier.excludedAccounts = excluded.sort((a, b) => a.site.localeCompare(b.site));

  // Profile enrichment: public contact/location fields the platforms expose.
  for (const h of kept) {
    const p = h.profile;
    if (!p) continue;
    if (p.email && !emails.includes(p.email.toLowerCase())) {
      emails.push(p.email.toLowerCase());
      identities.push({ source: h.site, detail: `public email on profile: ${p.email.toLowerCase()}` });
    }
    if (p.blog) identities.push({ source: h.site, detail: `profile blog: ${p.blog}` });
    if (p.twitter) identities.push({ source: h.site, detail: `profile twitter: ${p.twitter}` });
    if (p.location && !locations.includes(p.location)) locations.push(`${p.location} (self-declared on ${h.site})`);
    if (p.imageUrl && !photos.includes(p.imageUrl)) photos.push(p.imageUrl);
  }

  const weight = (h: UsernameHit) =>
    (h.confidence === 'high' ? 2 : h.confidence === 'medium' ? 1 : 0.5) +
    (h.identity === 'name-match' ? 2 : 0);
  const foundWeight = kept.reduce((acc, h) => acc + Math.max(weight(h), 0), 0);
  dossier.presenceScore = Math.min(100, Math.round((foundWeight / 40) * 100));

  // City-level public signals (Gravatar location text, NANP area notes) → map points.
  // Coarse geography only — this is footprint mapping, not device positioning.
  for (const loc of locations.slice(0, 3)) {
    const text = loc.replace(/^NANP area code \d+ \(region lookup: npa (\d+)\)$/, 'area code $1 region, North America');
    const geo = await geocodeText(text).catch(() => null);
    if (geo) {
      dossier.geoPoints.push({
        kind: 'osint',
        key: `osint:${loc}`,
        label: loc,
        detail: geo.label,
        lat: geo.lat,
        lon: geo.lon,
      });
    }
  }

  dossier.socialAccounts = kept.sort((a, b) => weight(b) - weight(a));
  dossier.dorks = personDorks({
    name: dossier.name,
    email,
    username: username || undefined,
    phone,
    domain,
  });
  dossier.parsed.url = parsedInput.url;
  dossier.durationMs = Date.now() - started;
  dossier.report = buildDossierReport(dossier);
  return dossier;
}

/** Fetch any URL through the local Tor circuit (clearnet or .onion) — used by the
 *  screening lane as the second path when a source WAF-blocks our primary egress. */
export async function torFetchAny(urlRaw: string, maxBytes = 400_000): Promise<{ url: string; status: number; body: string }> {
  const url = urlRaw.trim();
  if (!/^https?:\/\//i.test(url)) throw new Error('http(s) URL required');
  const tor = await torStatus();
  if (!tor.available) throw new Error(tor.note);
  let stdout = '';
  try {
    const out = await execFileP(
      'curl',
      ['--socks5-hostname', `127.0.0.1:${tor.port}`, '-sL', '--max-time', '40', '-A', UA, '-H', 'Accept: application/json,text/html;q=0.9,*/*;q=0.8', '-w', '\\n__T3MP3ST_STATUS__%{http_code}', url],
      { timeout: 45_000, maxBuffer: 32 * 1024 * 1024 }
    );
    stdout = out.stdout;
  } catch (e) {
    const err = e as { code?: number | string; stderr?: string; killed?: boolean };
    if (err.killed) throw new Error(`tor fetch timed out: ${url}`);
    const tail = (err.stderr || '').trim().slice(-120);
    throw new Error(`tor fetch failed (curl exit ${err.code ?? '?'})${tail ? `: ${tail}` : ''}`);
  }
  const marker = stdout.lastIndexOf('__T3MP3ST_STATUS__');
  const body = (marker >= 0 ? stdout.slice(0, marker) : stdout).slice(0, maxBytes);
  const status = marker >= 0 ? parseInt(stdout.slice(marker + 18).trim(), 10) || 0 : 0;
  return { url, status, body };
}

/** Fetch with automatic Tor fallback: primary egress first, Tor circuit when the
 *  source WAF-blocks it (403/000). Returns the winning body + which path answered. */
async function fetchWithTorFallback(url: string, init: RequestInit = {}): Promise<{ body: string; via: 'egress' | 'tor'; status: number }> {
  try {
    const res = await osintFetch(url, init);
    if (res.status !== 403) return { body: await res.text(), via: 'egress', status: res.status };
  } catch { /* fall through to Tor */ }
  const tor = await torStatus();
  if (tor.available) {
    const page = await torFetchAny(url);
    return { body: page.body, via: 'tor', status: page.status };
  }
  return { body: '', via: 'egress', status: 403 };
}

// --- subject screening — sanctions / watchlists / wanted notices (legal, public) ---

export interface ScreeningHit {
  source: string;
  kind: 'match' | 'notice';
  name: string;
  detail: string;
  url?: string;
}

export interface ScreeningSourceStatus {
  source: string;
  status: 'ok' | 'blocked' | 'unconfigured' | 'no-results';
  via?: 'egress' | 'tor';
  matches: ScreeningHit[];
  note?: string;
}

export interface ScreeningResult {
  name: string;
  sources: ScreeningSourceStatus[];
}

function normalizeName(n: string): string {
  return n.toLowerCase().replace(/[^a-z\s]/g, '').replace(/\s+/g, ' ').trim();
}

/** Screen a person across legal public sources: Interpol Red Notices and OFAC-type
 *  sanctions lists. Sources that WAF-block datacenter/Tor egress are reported as
 *  blocked — honestly — instead of pretending the check ran. */
export async function screenSubject(nameRaw: string): Promise<ScreeningResult> {
  const name = nameRaw.trim();
  if (!name || !name.includes(' ')) throw new Error('full name required (first + last)');
  const [firstName, ...rest] = name.split(/\s+/);
  const lastName = rest.join(' ');
  const sources: ScreeningSourceStatus[] = [];

  // Interpol Red Notices — public API
  try {
    const url = `https://ws-public.interpol.int/notices/v1/red?forename=${encodeURIComponent(firstName)}&name=${encodeURIComponent(lastName)}&limit=10`;
    const { body, via, status } = await fetchWithTorFallback(url, { headers: { accept: 'application/json' } });
    if (status !== 200) {
      sources.push({ source: 'Interpol Red Notices', status: 'blocked', matches: [], note: `HTTP ${status} — source blocks datacenter/Tor egress; check https://www.interpol.int/en/How-we-work/Notices/View-Red-Notices in your browser` });
    } else {
      const j = JSON.parse(body) as { total?: number; _embedded?: { notices?: Array<{ forename?: string; name?: string; date_of_birth?: string; nationalities?: string[]; _links?: { self?: { href?: string } } }> } };
      const notices = j._embedded?.notices || [];
      sources.push({
        source: 'Interpol Red Notices', status: notices.length ? 'ok' : 'no-results', via,
        matches: notices.slice(0, 10).map((n) => ({
          source: 'Interpol Red Notice', kind: 'notice' as const,
          name: `${n.forename || ''} ${n.name || ''}`.trim(),
          detail: `wanted notice${n.date_of_birth ? ` · DOB ${n.date_of_birth}` : ''}${n.nationalities?.length ? ` · ${n.nationalities.join(', ')}` : ''}`,
          url: n._links?.self?.href,
        })),
      });
    }
  } catch (e) {
    sources.push({ source: 'Interpol Red Notices', status: 'blocked', matches: [], note: String(e).slice(0, 120) });
  }

  // OFAC SDN list — official CSV export
  try {
    const { body, via, status } = await fetchWithTorFallback('https://www.treasury.gov/ofac/downloads/sdn.csv');
    if (status !== 200 || !body.startsWith('#') === false && body.length < 100) {
      sources.push({ source: 'OFAC SDN', status: 'blocked', matches: [], note: `export unreachable (HTTP ${status}) — browse https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list` });
    } else {
      const norm = normalizeName(name);
      const matches: ScreeningHit[] = [];
      for (const line of body.split('\n')) {
        if (line.startsWith('#') || !line.trim()) continue;
        const cols = line.split(',').map((c) => c.replace(/"/g, '').trim());
        const listName = normalizeName(cols[1] || '');
        if (!listName) continue;
        const tokens = norm.split(' ');
        if (tokens.every((t) => listName.includes(t)) && listName.length < norm.length + 40) {
          matches.push({
            source: 'OFAC SDN', kind: 'match', name: cols[1],
            detail: `${cols[2] || 'entity'}${cols[3] ? ` · program ${cols[3]}` : ''}${cols[5] ? ` · ${cols[5].slice(0, 140)}` : ''}`,
          });
          if (matches.length >= 10) break;
        }
      }
      sources.push({ source: 'OFAC SDN', status: matches.length ? 'ok' : 'no-results', via, matches });
    }
  } catch (e) {
    sources.push({ source: 'OFAC SDN', status: 'blocked', matches: [], note: String(e).slice(0, 120) });
  }

  // OpenSanctions — hosted API is keyed; report as unconfigured rather than pretending
  sources.push({
    source: 'OpenSanctions (full screening)', status: 'unconfigured', matches: [],
    note: 'hosted API needs a key (api.opensanctions.org) — free bulk datasets exist at data.opensanctions.org for air-gapped import',
  });

  return { name, sources };
}

// =============================================================================
// =============================================================================
// SEARCH EXTRACTION — mine search-engine results for contact data (keyless)
// =============================================================================
// Bing HTML SERP parses server-side (DDG/Mojeek serve challenges to datacenter
// exits; Bing answered 200 with real results). Titles + snippets are mined for
// emails, phones, social profile URLs — passive search-data extraction.

export interface SearchResultItem { title: string; url: string; snippet: string }

/** Parse Bing SERP HTML into result items (exported for unit tests). */
export function parseBingResults(html: string, max = 20): SearchResultItem[] {
  const out: SearchResultItem[] = [];
  const blocks = html.split('<li class="b_algo').slice(1);
  for (const block of blocks) {
    const anchor = block.match(/<h2[^>]*><a[^>]+href="(https?:\/\/[^"]+)"[^>]*>([\s\S]*?)<\/a>/);
    if (!anchor) continue;
    const url = anchor[1].replace(/&amp;/g, '&');
    const title = anchor[2].replace(/<[^>]+>/g, '').trim().slice(0, 200);
    const pMatch = block.match(/<p[^>]*>([\s\S]*?)<\/p>/);
    const snippet = pMatch ? pMatch[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim().slice(0, 400) : '';
    out.push({ title, url, snippet });
    if (out.length >= max) break;
  }
  return out;
}

export interface ExtractedContacts {
  emails: string[];
  phones: string[];
  socialUrls: string[];
}

const EMAIL_RE_GLOBAL = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
const PHONE_RE_GLOBAL = /(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}/g;
const SOCIAL_URL_RE = /https?:\/\/(?:www\.)?(github\.com|t\.me|twitter\.com|x\.com|instagram\.com|facebook\.com|linkedin\.com|tiktok\.com|youtube\.com|reddit\.com|soundcloud\.com|keybase\.io)\/[A-Za-z0-9_.\-/@]+/g;

/** Extract contact signals from arbitrary text (titles/snippets/URLs). */
export function extractContacts(text: string): ExtractedContacts {
  const emails = new Set<string>();
  const phones = new Set<string>();
  const socials = new Set<string>();
  for (const m of text.match(EMAIL_RE_GLOBAL) || []) {
    const e = m.toLowerCase().replace(/\.$/, '');
    if (/\.(png|jpe?g|gif|css|js|woff2?)$/.test(e)) continue;
    if (/(example\.com|sentry\.io|noreply|no-reply@|@2x)/.test(e)) continue;
    emails.add(e);
  }
  for (const m of text.match(PHONE_RE_GLOBAL) || []) {
    const digits = m.replace(/\D/g, '');
    if (digits.length === 11 && digits.startsWith('1')) phones.add(m.trim());
    else if (digits.length === 10 && !/^(19|20)\d{2}/.test(digits)) phones.add(m.trim());
  }
  for (const m of text.match(SOCIAL_URL_RE) || []) {
    const clean = m.replace(/[.,)]+$/, '');
    if (clean.split('/').filter(Boolean).length >= 2) socials.add(clean);
  }
  return { emails: [...emails], phones: [...phones], socialUrls: [...socials] };
}

/** Run a Bing search and extract contact signals from the results. */
export async function searchExtract(queryRaw: string): Promise<{ query: string; via: string; results: SearchResultItem[]; extracted: ExtractedContacts }> {
  const query = queryRaw.trim().slice(0, 200);
  if (!query) throw new Error('query required');
  const attempts: Array<() => Promise<string | null>> = [
    async () => {
      const res = await osintFetch(`https://www.bing.com/search?q=${encodeURIComponent(query)}&count=20`, {
        headers: { 'accept-language': 'en-US,en' },
        signal: AbortSignal.timeout(15_000),
      });
      return res.status === 200 ? await res.text() : null;
    },
    async () => {
      const tor = await torStatus();
      if (!tor.available) return null;
      const page = await torFetchAny(`https://www.bing.com/search?q=${encodeURIComponent(query)}&count=20`);
      return page.status === 200 ? page.body : null;
    },
  ];
  for (const attempt of attempts) {
    const html = await attempt().catch(() => null);
    if (!html) continue;
    const results = parseBingResults(html);
    if (results.length === 0) continue;
    const corpus = results.map((r) => `${r.title} ${r.snippet} ${r.url}`).join('\n');
    return { query, via: 'bing', results, extracted: extractContacts(corpus) };
  }
  return { query, via: 'blocked', results: [], extracted: { emails: [], phones: [], socialUrls: [] } };
}

// =============================================================================
// PEOPLE RECORDS — agent-driven browser scrubbing of public-records pages
// =============================================================================
// The agent renders public pages with a REAL Chromium (Playwright) — the same
// public data a person sees in their browser — and mines the text for structured
// records: age, city, address history, relatives, aliases. Public-record data,
// no login bypass, no stolen dumps. Source URL is kept on every record.

import * as fsPs from 'fs';
import * as pathPs from 'path';

export interface PersonRecord {
  name: string;
  age?: number;
  city?: string;
  pastAddresses: string[];
  relatives: string[];
  akas: string[];
  sourceUrl: string;
}

let peopleLaunchLock: Promise<void> | null = null;

function resolveChromiumExe(): string | null {
  const base = pathPs.join(process.env.LOCALAPPDATA || '', 'ms-playwright');
  if (!fsPs.existsSync(base)) return null;
  const dirs = fsPs.readdirSync(base).filter((d) => d.startsWith('chromium-')).sort().reverse();
  for (const dir of dirs) {
    for (const sub of ['chrome-win64', 'chrome-win']) {
      const exe = pathPs.join(base, dir, sub, 'chrome.exe');
      if (fsPs.existsSync(exe)) return exe;
    }
  }
  return null;
}

/** Parse FastPeopleSearch innerText into structured person records (exported for tests). */
export function parseFastPeopleSearch(text: string, sourceUrl: string, max = 10): PersonRecord[] {
  const records: PersonRecord[] = [];
  const blocks = text.split(/VIEW FREE DETAILS/).map((b) => b.trim()).filter(Boolean);
  const cityRe = /^[A-Za-z .'-]+, [A-Z]{2}$/;
  for (const block of blocks) {
    const lines = block.split(/\n+/).map((l) => l.trim()).filter((l) => l && !/^FastPeopleSearch$/.test(l) && !/FREE public records found/.test(l));
    let name = '';
    let pending = '';
    let age: number | undefined;
    let city = '';
    const pastAddresses: string[] = [];
    const relatives: string[] = [];
    const akas: string[] = [];
    for (const line of lines) {
      const ageCity = line.match(/^(?:(.{2,60}?)\s+)?Age (\d{1,3}) \u2022 (.+)$/);
      if (ageCity) {
        if (ageCity[1]) name = ageCity[1];
        else if (!name && pending) name = pending;
        age = parseInt(ageCity[2], 10);
        city = ageCity[3].split(/\s*\u2022\s*/)[0];
        continue;
      }
      const past = line.match(/^Past Addresses:\s*(.+)$/);
      if (past) { pastAddresses.push(...past[1].split(/\s*\u2022\s*/).map((s) => s.trim()).filter(Boolean)); continue; }
      const rel = line.match(/^Relatives:\s*(.+)$/);
      if (rel) { relatives.push(...rel[1].split(/\s*\u2022\s*/).map((s) => s.trim()).filter(Boolean)); continue; }
      const aka = line.match(/^AKA:\s*(.+)$/);
      if (aka) { akas.push(...aka[1].split(/\s*\u2022\s*/).map((s) => s.trim()).filter(Boolean)); continue; }
      if (!name && cityRe.test(line) && !city) { city = line; continue; }
      if (!name && line.length <= 60 && !/^(Find |Names |VIEW)/.test(line)) pending = line;
    }
    if (!name && pending) name = pending;
    if (!name && !city) continue;
    if (/(©|copyright|all rights reserved)/i.test(name)) continue;
    records.push({ name: name || city, age, city: city || undefined, pastAddresses, relatives, akas, sourceUrl });
    if (records.length >= max) break;
  }
  return records;
}

/** Parse TruePeopleSearch innerText into structured records.
 *  Layout: header rows, then per-record: name line, 'Age [N|Unknown] • City, ST',
 *  optional 'Used to live in A, B, C', optional 'Related to A, B', 'View Details'. */
export function parseTruePeopleSearch(text: string, sourceUrl: string, max = 10): PersonRecord[] {
  const records: PersonRecord[] = [];
  const lines = text.split(/\n+/).map((l) => l.trim()).filter(Boolean);
  let pending = '';
  let cur: PersonRecord | null = null;
  const finish = () => {
    if (cur && (cur.name || cur.city)) {
      if (!/(©|copyright)/i.test(cur.name)) records.push(cur);
    }
    cur = null;
  };
  for (const line of lines) {
    if (/^TruePeopleSearch$/.test(line) || /^(Name|Phone|Address|Email|Neighbors)$/.test(line)) continue;
    if (/records? found for/i.test(line)) continue;
    const ageN = line.match(/^Age (\d{1,3})\s*•\s*(.+)$/i);
    const ageUnknown = line.match(/^Age Unknown\s*•\s*(.+)$/i);
    if (ageN || ageUnknown) {
      finish();
      cur = {
        name: pending,
        age: ageN ? parseInt(ageN[1], 10) : undefined,
        city: (ageN ? ageN[2] : ageUnknown![1]).trim(),
        pastAddresses: [], relatives: [], akas: [], sourceUrl,
      };
      pending = '';
      continue;
    }
    const usedTo = line.match(/^Used to live in\s*(.+)$/i);
    if (usedTo && cur) { cur.pastAddresses.push(...usedTo[1].split(/,\s*/).map((s) => s.trim()).filter(Boolean)); continue; }
    const related = line.match(/^Related to\s*(.+)$/i);
    if (related && cur) { cur.relatives.push(...related[1].split(/,\s*/).map((s) => s.trim()).filter(Boolean)); continue; }
    if (/^View Details/i.test(line)) { finish(); continue; }
    if (!cur) pending = line;
  }
  finish();
  return records.slice(0, max);
}

/** Per-name result cache — public-records sites throttle frequent queries; a cached
 *  hit is always better than a soft-blocked empty one. 10 min TTL. */
const peopleCache = new Map<string, { at: number; records: PersonRecord[] }>();
const PEOPLE_CACHE_TTL = 10 * 60 * 1000;

/** Render the public-records page for a name in a real browser and mine it. */
export async function peopleRecordSearch(fullNameRaw: string): Promise<{ name: string; via: string; records: PersonRecord[]; note?: string }> {
  const fullName = fullNameRaw.trim().replace(/s+/g, ' ');
  if (!fullName || !fullName.includes(' ')) throw new Error('full name required (first + last)');
  const exe = resolveChromiumExe();
  if (!exe) throw new Error('playwright chromium not installed — run: npx playwright install chromium');
  const cacheKey0 = fullName.toLowerCase();
  const cached = peopleCache.get(cacheKey0);
  if (cached && Date.now() - cached.at < PEOPLE_CACHE_TTL) {
    return { name: fullName, via: 'fastpeoplesearch (rendered)', records: cached.records, note: 'cached (source throttles frequent queries)' };
  }
  const run = async (): Promise<PersonRecord[]> => {
    const { chromium } = await import('playwright');
    const browser = await chromium.launch({ headless: true, executablePath: exe });
    try {
      const page = await browser.newPage({
        userAgent: UA,
        viewport: { width: 1366, height: 900 },
      });
      const slug = fullName.toLowerCase().replace(/\s+/g, '-');
      // Source 1: TruePeopleSearch — renders for datacenter exits more reliably.
      const tpsUrl = `https://www.truepeoplesearch.com/results?name=${encodeURIComponent(fullName)}`;
      await page.goto(tpsUrl, { timeout: 30_000, waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(6_000);
      let tpsText = (await page.evaluate('document.body.innerText.slice(0, 60000)')) as string;
      let parsed = parseTruePeopleSearch(tpsText, tpsUrl, 10);
      if (parsed.length > 0) return parsed;
      // TPS late render / soft block — one retry window.
      await page.waitForTimeout(5_000);
      tpsText = (await page.evaluate('document.body.innerText.slice(0, 60000)')) as string;
      parsed = parseTruePeopleSearch(tpsText, tpsUrl, 10);
      if (parsed.length > 0) return parsed;
      // Source 2: FastPeopleSearch.
      const fpsUrl = `https://www.fastpeoplesearch.com/name/${slug}`;
      await page.goto(fpsUrl, { timeout: 30_000, waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(4_000);
      let fpsText = (await page.evaluate('document.body.innerText.slice(0, 60000)')) as string;
      parsed = parseFastPeopleSearch(fpsText, fpsUrl, 10);
      if (parsed.length === 0) {
        await page.waitForTimeout(6_000);
        fpsText = (await page.evaluate('document.body.innerText.slice(0, 60000)')) as string;
        parsed = parseFastPeopleSearch(fpsText, fpsUrl, 10);
      }
      return parsed;
    } finally {
      await browser.close().catch(() => undefined);
    }
  };
  // One browser launch at a time.
  const records = peopleLaunchLock
    ? await peopleLaunchLock.then(run)
    : await run();
  const cacheKey = fullName.toLowerCase();
  peopleCache.set(cacheKey, { at: Date.now(), records });
  return { name: fullName, via: 'fastpeoplesearch (rendered)', records };
}

// AGENT-RUNNABLE TOOLS (registered into the arsenal, category 'osint')
// =============================================================================

function fmtSweep(sweep: SweepResult): string {
  const lines = sweep.found.map((h) => {
    const ident = h.identity === 'name-match' ? ' [✓ IDENTITY MATCH]' : h.identity === 'name-mismatch' ? ' [≠ name mismatch — likely someone else]' : '';
    const dn = h.profile?.displayName ? ` — "${h.profile.displayName}"` : '';
    return `  [${h.confidence}] ${h.site}${ident}: ${h.url}${dn}`;
  });
  const corroborated = sweep.found.filter((h) => h.identity === 'name-match').length;
  const mismatched = sweep.found.filter((h) => h.identity === 'name-mismatch').length;
  return [
    `Username sweep for "${sweep.username}": ${sweep.found.length} found (${corroborated} corroborated as subject, ${mismatched} mismatched) / ${sweep.absent} absent / ${sweep.unknown.length} unknown (${sweep.checked} sites, ${sweep.durationMs}ms)`,
    ...lines,
    sweep.unknown.length ? `  unknown: ${sweep.unknown.map((u) => u.site).join(', ')}` : '',
  ].filter(Boolean).join('\n');
}

export const OSINT_TOOLS: CustomTool[] = [
  {
    name: 'osint_username_sweep',
    description: 'Sweep a username across 60+ public social/developer/gaming sites (public profile probes, keyless). Returns claimed accounts.',
    category: 'osint',
    parameters: [
      { name: 'username', type: 'string', description: 'Username to sweep (no @)', required: true },
      { name: 'sites', type: 'string', description: 'Comma-separated site names to limit the sweep (default: all)', required: false },
      { name: 'name', type: 'string', description: 'Known full name of the subject — enables identity corroboration on hits (recommended)', required: false },
    ],
    handler: async (context) => {
      const username = context.parameters.username as string;
      const sites = (context.parameters.sites as string | undefined)?.split(',').map((s) => s.trim()).filter(Boolean);
      const name = context.parameters.name as string | undefined;
      try {
        const sweep = await runUsernameSweep(username, { sites, hints: { name } });
        const findings = sweep.found.slice(0, 20).map((h) => ({
          title: `Social Account Found — ${h.site} (${sweep.username})`,
          severity: 'info' as const,
          details: `Username "${sweep.username}" is claimed on ${h.site}: ${h.url} (probe ${h.probeStatus ?? '?'}, confidence ${h.confidence})`,
        }));
        return {
          success: true,
          output: fmtSweep(sweep),
          findings,
        };
      } catch (error) {
        return { success: false, error: `Username sweep failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_email_lookup',
    description: 'Email intelligence: Gravatar identity (name, location, linked accounts, photo), breach exposure (XposedOrNot + LeakCheck public), and mail-domain MX/A records.',
    category: 'osint',
    parameters: [
      { name: 'email', type: 'string', description: 'Email address to investigate', required: true },
    ],
    handler: async (context) => {
      const email = context.parameters.email as string;
      try {
        const intel = await emailIntel(email);
        const lines = [
          `Email intel for ${intel.email}:`,
          `Gravatar: ${intel.gravatar.exists ? 'EXISTS' : 'none'}${intel.gravatar.displayName ? ` — ${intel.gravatar.displayName}` : ''}${intel.gravatar.location ? ` (${intel.gravatar.location})` : ''}`,
          ...(intel.gravatar.accounts || []).map((a) => `  linked account: ${a.shortname}: ${a.username || ''} ${a.url}`),
          `Domain ${intel.domain?.name ?? '?'}: ${intel.domain?.acceptsMail ? `mail (MX: ${intel.domain.mxRecords.join(', ')})` : 'no MX'}${intel.domain?.aRecord ? `, A ${intel.domain.aRecord}` : ''}`,
          ...intel.breaches.map((b) => `Breaches ${b.service}: ${b.found === 'unknown' ? 'unknown' : b.found}${b.sources?.length ? ` (${b.sources.slice(0, 5).join('; ')})` : ''}`),
        ];
        const findings = [];
        if (intel.gravatar.exists) {
          findings.push({
            title: `Gravatar Identity — ${intel.email}`,
            severity: 'info' as const,
            details: `Gravatar exists${intel.gravatar.displayName ? ` for ${intel.gravatar.displayName}` : ''}${intel.gravatar.location ? `, location ${intel.gravatar.location}` : ''}; avatar ${intel.gravatar.avatarUrl}${intel.gravatar.accounts?.length ? `; linked accounts: ${intel.gravatar.accounts.map((a) => `${a.shortname}=${a.username || a.url}`).join(', ')}` : ''}`,
          });
        }
        for (const b of intel.breaches) {
          if (typeof b.found === 'number' && b.found > 0) {
            findings.push({
              title: `Breach Exposure — ${intel.email} (${b.service})`,
              severity: 'medium' as const,
              details: `${b.found} exposed records${b.sources?.length ? ` from: ${b.sources.slice(0, 8).join(', ')}` : ''}${b.fields?.length ? `; fields: ${b.fields.join(', ')}` : ''}`,
            });
          }
        }
        return { success: true, output: lines.filter(Boolean).join('\n'), findings };
      } catch (error) {
        return { success: false, error: `Email lookup failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_phone_lookup',
    description: 'Phone number intelligence: E.164 normalization, country/carrier-plan routing, NANP area-code validation, and reverse-lookup deep links (Truecaller, Sync.me, engines).',
    category: 'osint',
    parameters: [
      { name: 'phone', type: 'string', description: 'Phone number (any common format)', required: true },
    ],
    handler: async (context) => {
      const phone = context.parameters.phone as string;
      try {
        const intel = phoneIntel(phone);
        const lines = [
          `Phone intel for ${intel.input}:`,
          `E.164: ${intel.e164} — country ${intel.country} (expected ${intel.expectedLength} national digits, got ${intel.digits.length - intel.countryCode.length})`,
          intel.nanp ? `NANP area ${intel.nanp.areaCode}, exchange ${intel.nanp.exchange}, area valid: ${intel.nanp.validAreaCode}` : '',
          ...intel.searchLinks.map((l) => `  ${l.label}: ${l.url}`),
        ];
        return {
          success: true,
          output: lines.filter(Boolean).join('\n'),
          findings: [{
            title: `Phone Parsed — ${intel.e164}`,
            severity: 'info' as const,
            details: `${intel.country}; length ${intel.lengthValid ? 'valid' : 'UNEXPECTED'}${intel.nanp ? `; NANP area ${intel.nanp.areaCode} (valid: ${intel.nanp.validAreaCode})` : ''}`,
          }],
        };
      } catch (error) {
        return { success: false, error: `Phone lookup failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_breach_lookup',
    description: 'Breach/dump exposure check for an email, username, phone — or a raw password (HIBP Pwned Passwords, k-anonymity). Free lanes always run; keyed dump lanes (LeakCheck v2/DeHashed/Snusbase) run when operator keys are configured.',
    category: 'osint',
    parameters: [
      { name: 'query', type: 'string', description: 'Email, username, phone (E.164), or password', required: true },
      { name: 'kind', type: 'string', description: 'Query type', required: false, enum: ['email', 'username', 'phone', 'password'], default: 'email' },
    ],
    handler: async (context) => {
      const query = context.parameters.query as string;
      const kind = (context.parameters.kind as 'email' | 'username' | 'phone' | 'password') || (query.includes('@') ? 'email' : 'username');
      try {
        const result = await dumpDatabaseLookup(query, kind);
        const lines = [
          `Dump-database lookup (${kind}) for "${result.query}":`,
          ...result.free.map((f) => `  ${f.service}: ${f.found === 'unknown' ? 'unknown' : f.found}${f.sources?.length ? ` (${f.sources.slice(0, 5).join('; ')})` : ''}${f.note ? ` — ${f.note}` : ''}`),
          ...result.deep.map((d) => 'status' in d
            ? `  ${d.service}: NOT RUN — ${d.note}`
            : `  ${d.service}: ${d.found} records${d.records?.length ? `\n${d.records.slice(0, 10).map((r) => `    ${r.email || r.username || '?'}${r.password ? ' :PASSWORD:' : ''}${r.hash ? ' :HASH:' : ''} ${r.password || r.hash || ''} (${r.source || '?'})`).join('\n')}` : ''}`),
        ];
        const findings = [];
        for (const f of result.free) {
          if (typeof f.found === 'number' && f.found > 0) {
            findings.push({
              title: `Breach Exposure — ${result.query} (${f.service})`,
              severity: 'medium' as const,
              details: `${f.found} records${f.sources?.length ? ` from ${f.sources.slice(0, 8).join(', ')}` : ''}${f.fields?.length ? `; leaked fields: ${f.fields.join(', ')}` : ''}`,
            });
          }
        }
        return {
          success: true,
          output: lines.join('\n'),
          findings,
          credentials: result.credentials.length ? result.credentials : undefined,
        };
      } catch (error) {
        return { success: false, error: `Breach lookup failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_infostealer_check',
    description: 'Check an email against Hudson Rock\'s free cybercrime-intelligence feed for LIVE infostealer infections (malware family, compromise date, computer name, IP, OS, installed software). Keyless — a live-compromise class static dump lanes cannot see.',
    category: 'osint',
    parameters: [
      { name: 'email', type: 'string', description: 'Email address to check', required: true },
    ],
    handler: async (context) => {
      const email = context.parameters.email as string;
      try {
        const r = await hudsonRockEmail(email);
        const lines = [
          `Infostealer check — ${email}:`,
          r.infected
            ? `  INFECTED — ${r.infections.length} infection record(s); corporate services on record: ${r.corporateServices}, user services: ${r.userServices}`
            : `  no infostealer infection on record${r.note ? ` — ${r.note}` : ''}`,
          ...r.infections.map((i) => `  ${i.family || '?'} · ${i.date || '?'} · host=${i.computerName || '?'} · ip=${i.ip || '?'}${i.os ? ` · os=${i.os}` : ''}${i.software?.length ? ` · software=${i.software.slice(0, 6).join(', ')}` : ''}`),
        ];
        const findings = r.infected
          ? [{
            title: `Infostealer Infection — ${email}`,
            severity: 'high' as const,
            details: r.infections.map((i) => `${i.family || 'stealer'} on ${i.computerName || '?'} (${i.ip || '?'}) at ${i.date || '?'}`).join('; '),
          }]
          : [];
        return { success: true, output: lines.join('\n'), findings };
      } catch (error) {
        return { success: false, error: `Infostealer check failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_breach_catalog',
    description: 'Query the HIBP breach catalogue (keyless): every known breach touching a domain, with dates, account counts and leaked data classes. Pass "all" for the full universe. Answers "was this domain ever breached" with zero account keys.',
    category: 'osint',
    parameters: [
      { name: 'domain', type: 'string', description: 'Breached domain to query (e.g. adobe.com), or "all" for the full catalogue', required: true },
    ],
    handler: async (context) => {
      const raw = String(context.parameters.domain || '').trim();
      const domain = !raw || raw.toLowerCase() === 'all' ? undefined : raw;
      try {
        const c = await hibpBreachCatalog(domain);
        const lines = [
          `HIBP breach catalogue${c.domain ? ` for ${c.domain}` : ''} — ${c.total} breach(es)${c.note ? ` (${c.note})` : ''}:`,
          ...c.entries.slice(0, 25).map((e) => `  ${e.name} · ${e.breachDate || '?'} · ${e.pwnCount ? e.pwnCount.toLocaleString() : '?'} accounts${e.dataClasses?.length ? ` · leaked: ${e.dataClasses.slice(0, 8).join(', ')}` : ''}`),
          c.total > 25 ? `  … ${c.total - 25} more (ask again with a domain filter to narrow)` : '',
        ];
        const findings = c.total > 0
          ? [{
            title: `Breach Catalogue — ${c.domain || 'all known breaches'} (${c.total} entries)`,
            severity: 'info' as const,
            details: c.entries.slice(0, 10).map((e) => `${e.name} (${e.breachDate || '?'}, ${e.pwnCount || '?'} accounts)`).join('; '),
          }]
          : [];
        return { success: true, output: lines.filter(Boolean).join('\n'), findings };
      } catch (error) {
        return { success: false, error: `Breach catalogue failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_person_locate',
    description: 'Full person locator: auto-parses an email/username/phone/URL/name, sweeps socials, pulls Gravatar identity + linked accounts, runs breach/dump lanes on every identifier, and returns a scored dossier.',
    category: 'osint',
    parameters: [
      { name: 'subject', type: 'string', description: 'Anything: email, @handle, phone, profile URL, domain, or full name', required: true },
      { name: 'name', type: 'string', description: 'Known full name (improves dork generation)', required: false },
    ],
    handler: async (context) => {
      const subject = context.parameters.subject as string;
      const name = context.parameters.name as string | undefined;
      try {
        const dossier = await locatePerson({ subject, name });
        const lines = [
          `LOCATOR DOSSIER — ${dossier.subject} (${dossier.durationMs}ms, presence ${dossier.presenceScore}/100)`,
          `Parsed: ${Object.entries(dossier.parsed).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join(' ') || 'nothing'}`,
          `Socials (${dossier.socialAccounts.length}):`,
          ...dossier.socialAccounts.map((h) => `  [${h.confidence}] ${h.site}: ${h.url}`),
          dossier.gravatar?.exists ? `Gravatar: ${dossier.gravatar.displayName || '(no name)'}${dossier.gravatar.location ? ` @ ${dossier.gravatar.location}` : ''}` : 'Gravatar: none',
          dossier.phone ? `Phone: ${dossier.phone.e164} (${dossier.phone.country})` : '',
          ...dossier.dumpLanes.map((lane) => `Dump lane (${lane.kind}): ` + lane.free.map((f) => `${f.service}=${f.found}`).join(', ') + lane.deep.map((d) => `; ${d.service}=${'status' in d ? d.status : d.found}`).join('')),
          ...dossier.identities.map((i) => `  identity: ${i.source}: ${i.detail}`),
          ...dossier.dorks.slice(0, 8).map((d) => `  dork ${d.label}: ${d.url}`),
        ];
        const findings = [];
        if (dossier.socialAccounts.length > 0) {
          findings.push({
            title: `OSINT Dossier — ${dossier.subject} (${dossier.socialAccounts.length} accounts)`,
            severity: 'info' as const,
            details: dossier.socialAccounts.map((h) => `${h.site}: ${h.url}`).join('\n'),
          });
        }
        const credentials = dossier.dumpLanes.flatMap((l) => l.credentials);
        return {
          success: true,
          output: lines.filter(Boolean).join('\n'),
          findings,
          credentials: credentials.length ? credentials : undefined,
        };
      } catch (error) {
        return { success: false, error: `Person locate failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_username_permutate',
    description: 'Generate username permutations from a real name (first.last, flast, first_last, year suffixes…) for hunting handle variants across platforms.',
    category: 'osint',
    parameters: [
      { name: 'first', type: 'string', description: 'First name', required: true },
      { name: 'last', type: 'string', description: 'Last name', required: true },
      { name: 'middle', type: 'string', description: 'Middle name/initial', required: false },
      { name: 'birthYear', type: 'string', description: 'Birth year (4 digits) for suffix variants', required: false },
      { name: 'numbers', type: 'boolean', description: 'Add numeric suffix variants (default true)', required: false },
    ],
    handler: async (context) => {
      try {
        const perms = usernamePermutations(
          context.parameters.first as string,
          context.parameters.last as string,
          {
            middle: context.parameters.middle as string | undefined,
            birthYear: context.parameters.birthYear as string | undefined,
            numbers: context.parameters.numbers as boolean | undefined,
          }
        );
        return {
          success: true,
          output: `${perms.length} username permutations:\n${perms.join('\n')}`,
        };
      } catch (error) {
        return { success: false, error: `Permutation failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_people_records',
    description: 'Render the public-records page for a full name in a real browser (Playwright Chromium) and mine structured person records: age, city, address history, relatives, aliases. Pass the subject full name.',
    category: 'osint',
    parameters: [
      { name: 'name', type: 'string', description: 'Full name (first + last)', required: true },
    ],
    handler: async (context) => {
      const name = context.parameters.name as string;
      try {
        const result = await peopleRecordSearch(name);
        const lines = [
          `Public records for "${result.name}" (${result.via}): ${result.records.length} record(s)`,
          ...result.records.map((r) => `  ${r.name}${r.age ? `, age ${r.age}` : ''}${r.city ? ` — ${r.city}` : ''}\n    addresses: ${r.pastAddresses.join(' | ') || '—'}\n    relatives: ${r.relatives.join(', ') || '—'}\n    akas: ${r.akas.join(', ') || '—'}\n    source: ${r.sourceUrl}`),
        ];
        const findings = result.records.slice(0, 5).map((r) => ({
          title: `Public Record — ${r.name}${r.city ? `, ${r.city}` : ''}`,
          severity: 'info' as const,
          details: `age ${r.age ?? '?'}; addresses: ${r.pastAddresses.join(' | ') || '—'}; relatives: ${r.relatives.join(', ') || '—'}; akas: ${r.akas.join(', ') || '—'}; source: ${r.sourceUrl}`,
        }));
        return { success: true, output: lines.join('\n'), findings };
      } catch (error) {
        return { success: false, error: `People records failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_darkweb_leak_monitor',
    description: 'Ransomware leak-site monitor: check the ransomware groups\' own victim posts (ransomware.live, keyless) for a target domain or company name. The free alternative to paid dark-web monitoring.',
    category: 'osint',
    parameters: [
      { name: 'keyword', type: 'string', description: 'Target domain or company name to look for on leak sites', required: true },
    ],
    handler: async (context) => {
      const keyword = context.parameters.keyword as string;
      try {
        const result = await ransomwareLeakSearch(keyword);
        const lines = [
          `Leak-site monitor (${result.searched}) for "${result.keyword}": ${result.found} victim post(s)`,
          ...result.victims.slice(0, 15).map((v) => `  [${v.group}] ${v.victim}${v.domain ? ` (${v.domain})` : ''}${v.attackDate ? ` — attacked ${v.attackDate.slice(0, 10)}` : ''}${v.postUrl ? ` — ${v.postUrl}` : ''}${v.description ? `\n      ${v.description}` : ''}`),
          result.note ? `  note: ${result.note}` : '',
        ];
        const findings = result.victims.slice(0, 10).map((v) => ({
          title: `Leak-Site Victim Post — ${v.victim} (${v.group})`,
          severity: 'medium' as const,
          details: `${v.victim}${v.domain ? ` (${v.domain})` : ''} listed by ransomware group ${v.group}${v.attackDate ? `, attacked ${v.attackDate.slice(0, 10)}` : ''}${v.description ? ` — ${v.description}` : ''}${v.postUrl ? ` Post: ${v.postUrl}` : ''}`,
        }));
        return { success: true, output: lines.filter(Boolean).join('\n'), findings };
      } catch (error) {
        return { success: false, error: `Leak monitor failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_onion_search',
    description: 'Search onion (Tor hidden-service) sites via Ahmia, the public onion search engine. Runs DIRECT over a local Tor circuit when one is up (9050/9150), otherwise over clearnet ahmia.fi — reports honestly if the exit is blocked.',
    category: 'osint',
    parameters: [
      { name: 'query', type: 'string', description: 'Search terms for the onion index', required: true },
    ],
    handler: async (context) => {
      const query = context.parameters.query as string;
      try {
        const result = await ahmiaSearch(query);
        const lines = [
          `Onion search "${result.query}" via ${result.via}: ${result.results.length} result(s)`,
          ...result.results.map((r) => `  ${r.title}\n    ${r.url}${r.snippet ? `\n    ${r.snippet}` : ''}`),
          result.note ? `  note: ${result.note}` : '',
        ];
        return { success: true, output: lines.filter(Boolean).join('\n') };
      } catch (error) {
        return { success: false, error: `Onion search failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_onion_fetch',
    description: 'Fetch a .onion page directly through the local Tor circuit (curl --socks5-hostname). Requires a running Tor daemon or Tor Browser. Public hidden-service content only.',
    category: 'osint',
    parameters: [
      { name: 'url', type: 'string', description: 'Full .onion URL', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;
      try {
        const page = await onionFetch(url);
        return {
          success: true,
          output: `GET ${page.url} → HTTP ${page.status}\n\n${page.body.slice(0, 4000)}`,
        };
      } catch (error) {
        return { success: false, error: `Onion fetch failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
];
