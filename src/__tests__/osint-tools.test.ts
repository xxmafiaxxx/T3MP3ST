import { describe, it, expect } from 'vitest';
import {
  OSINT_SITES,
  OSINT_TOOLS,
  runUsernameSweep,
  usernamePermutations,
  phoneIntel,
  personDorks,
  validateUsername,
  isPrivateIp,
  ipGeo,
  geocodeText,
} from '../tools/osint.js';

describe('osint site catalog', () => {
  it('every site is well-formed with unique names and valid probe configs', () => {
    const names = new Set<string>();
    expect(OSINT_SITES.length).toBeGreaterThanOrEqual(55);
    for (const s of OSINT_SITES) {
      expect(names.has(s.name), `duplicate site name ${s.name}`).toBe(false);
      names.add(s.name);
      expect(s.urlTemplate).toContain('{u}');
      expect(s.probeUrlTemplate).toContain('{u}');
      expect(['status', 'body_contains', 'json_array_nonempty', 'json_field']).toContain(s.probeType);
      expect(['high', 'medium', 'low']).toContain(s.reliability);
      // body/json probes need a discriminator value to be meaningful
      if (s.probeType === 'body_contains' || s.probeType === 'json_field') {
        expect(s.probeValue).toBeTruthy();
      }
    }
  });

  it('covers the flagship platforms', () => {
    const names = new Set(OSINT_SITES.map((s) => s.name));
    for (const expected of ['GitHub', 'Reddit', 'TikTok', 'Telegram', 'Keybase', 'chess.com', 'Steam', 'SoundCloud', 'Bluesky']) {
      expect(names.has(expected), `missing flagship site ${expected}`).toBe(true);
    }
  });
});

describe('osint agent tools', () => {
  it('registers 10 tools in the osint category with required parameters', () => {
    expect(OSINT_TOOLS.length).toBe(10);
    const names = new Set<string>();
    for (const t of OSINT_TOOLS) {
      expect(names.has(t.name), `duplicate tool ${t.name}`).toBe(false);
      names.add(t.name);
      expect(t.category).toBe('osint');
      expect(typeof t.handler).toBe('function');
      const required = (t.parameters || []).filter((p) => p.required);
      expect(required.length).toBeGreaterThanOrEqual(1);
    }
    for (const expected of [
      'osint_username_sweep',
      'osint_email_lookup',
      'osint_phone_lookup',
      'osint_breach_lookup',
      'osint_person_locate',
      'osint_username_permutate',
      'osint_darkweb_leak_monitor',
      'osint_onion_search',
      'osint_onion_fetch',
      'osint_people_records',
    ]) {
      expect(names.has(expected), `missing tool ${expected}`).toBe(true);
    }
  });

  it('sweep tool validates the username and rejects garbage', async () => {
    const sweep = OSINT_TOOLS.find((t) => t.name === 'osint_username_sweep')!;
    const bad = await sweep.handler({
      parameters: { username: 'not/valid##' },
      target: undefined,
    } as never);
    expect(bad.success).toBe(false);
    expect(bad.error).toMatch(/Invalid username/i);
  });

  it('permutate tool generates handle variants from a real name', async () => {
    const perm = OSINT_TOOLS.find((t) => t.name === 'osint_username_permutate')!;
    const res = await perm.handler({
      parameters: { first: 'John', last: 'Smith', birthYear: '1990' },
    } as never);
    expect(res.success).toBe(true);
    expect(res.output).toContain('johnsmith');
    expect(res.output).toContain('jsmith');
    expect(res.output).toContain('john.smith');
    expect(res.output).toContain('johnsmith1990');
  });
});

describe('username sweep classification', () => {
  it('classifies found/absent/unknown against a live local stub (all four probe types)', async () => {
    // Local stub standing in for four platform shapes: a status-probe hit (200),
    // a status-probe miss (404), a login-wall block (403 → unknown), a soft-404
    // body page (Telegram style), and a JSON array endpoint (GitLab style) —
    // proves the probe classifier without touching any real service.
    const { createServer } = await import('node:http');
    const srv = createServer((req, res) => {
      const path = req.url || '';
      if (path.startsWith('/status-ok')) { res.statusCode = 200; res.end('hello'); }
      else if (path.startsWith('/status-gone')) { res.statusCode = 404; res.end('nope'); }
      else if (path.startsWith('/blocked')) { res.statusCode = 403; res.end('forbidden'); }
      else if (path.startsWith('/soft-miss')) {
        res.statusCode = 200;
        res.end('<html>If you don\'t have Telegram... <b>no marker here</b></html>');
      } else if (path.startsWith('/soft-hit')) {
        res.statusCode = 200;
        res.end('<html><div class="tgme_page_title">Stub User</div></html>');
      } else if (path.startsWith('/arr-empty')) { res.statusCode = 200; res.end('[]'); }
      else if (path.startsWith('/arr-hit')) { res.statusCode = 200; res.end('[{"id":1}]'); }
      else { res.statusCode = 404; res.end(); }
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    const port = (srv.address() as { port: number }).port;
    const base = `http://127.0.0.1:${port}`;
    try {
      const sweep = await runUsernameSweep('stubuser', {
        customSites: [
          { name: 'StubStatusHit', category: 'social', urlTemplate: base + '/status-ok/{u}', probeUrlTemplate: base + '/status-ok/{u}', probeType: 'status', reliability: 'high' },
          { name: 'StubStatusMiss', category: 'social', urlTemplate: base + '/status-gone/{u}', probeUrlTemplate: base + '/status-gone/{u}', probeType: 'status', reliability: 'high' },
          { name: 'StubBlocked', category: 'social', urlTemplate: base + '/blocked/{u}', probeUrlTemplate: base + '/blocked/{u}', probeType: 'status', reliability: 'medium' },
          { name: 'StubSoft404Miss', category: 'messaging', urlTemplate: base + '/soft-miss/{u}', probeUrlTemplate: base + '/soft-miss/{u}', probeType: 'body_contains', probeValue: 'tgme_page_title', reliability: 'high' },
          { name: 'StubSoft404Hit', category: 'messaging', urlTemplate: base + '/soft-hit/{u}', probeUrlTemplate: base + '/soft-hit/{u}', probeType: 'body_contains', probeValue: 'tgme_page_title', reliability: 'high' },
          { name: 'StubArrMiss', category: 'dev', urlTemplate: base + '/arr-empty/{u}', probeUrlTemplate: base + '/arr-empty/{u}', probeType: 'json_array_nonempty', reliability: 'high' },
          { name: 'StubArrHit', category: 'dev', urlTemplate: base + '/arr-hit/{u}', probeUrlTemplate: base + '/arr-hit/{u}', probeType: 'json_array_nonempty', reliability: 'high' },
        ],
      });

      const bySite = new Map(sweep.found.map((h) => [h.site, h]));
      expect(bySite.get('StubStatusHit')!.status).toBe('found');
      expect(bySite.get('StubSoft404Hit')!.status).toBe('found');
      expect(bySite.get('StubArrHit')!.status).toBe('found');
      expect(sweep.absent).toBe(3);
      const unknown = sweep.unknown.map((u) => u.site);
      expect(unknown).toContain('StubBlocked');
      expect(sweep.checked).toBe(7);
    } finally {
      await new Promise<void>((r) => srv.close(() => r()));
    }
  });

  it('a site filter that matches nothing fails honestly', async () => {
    await expect(runUsernameSweep('someuser', { sites: ['__never_matches__'] })).rejects.toThrow(/no sites/i);
  });

  it('validateUsername strips @ and rejects path characters', () => {
    expect(validateUsername('@handle')).toBe('handle');
    expect(validateUsername('normal_user.1')).toBe('normal_user.1');
    expect(validateUsername('a/b')).toBeNull();
    expect(validateUsername('')).toBeNull();
    expect(validateUsername('x'.repeat(65))).toBeNull();
  });
});

describe('phone intel', () => {
  it('normalizes NANP numbers and validates the area code', () => {
    const p = phoneIntel('(718) 555-0199');
    expect(p.e164).toBe('+17185550199');
    expect(p.countryCode).toBe('1');
    expect(p.nanp).not.toBeNull();
    expect(p.nanp!.areaCode).toBe('718');
    expect(p.nanp!.validAreaCode).toBe(true);
    expect(p.searchLinks.some((l) => l.url.includes('truecaller'))).toBe(true);
  });

  it('routes international prefixes to the right country', () => {
    expect(phoneIntel('+44 20 7946 0958').country).toContain('United Kingdom');
    expect(phoneIntel('+49 30 901820').country).toContain('Germany');
    expect(phoneIntel('+8687654321').country).toContain('China');
  });

  it('flags invalid NANP area codes (N11 / leading 0/1)', () => {
    expect(phoneIntel('9115550199').nanp!.validAreaCode).toBe(false);
    expect(phoneIntel('0115550199').nanp!.validAreaCode).toBe(false);
  });

  it('rejects garbage', () => {
    expect(() => phoneIntel('123')).toThrow();
    expect(() => phoneIntel('not a phone at all')).toThrow();
  });
});

describe('username permutations', () => {
  it('generates the classic handle shapes with year suffixes', () => {
    const perms = usernamePermutations('John', 'Smith', { birthYear: '1990' });
    const set = new Set(perms);
    for (const expected of ['johnsmith', 'smithjohn', 'john.smith', 'john_smith', 'jsmith', 'johns', 'johnsmith1990', 'johnsmith90']) {
      expect(set.has(expected), `missing permutation ${expected}`).toBe(true);
    }
  });

  it('honors the max cap', () => {
    const perms = usernamePermutations('Al', 'Bee', { max: 10 });
    expect(perms.length).toBeLessThanOrEqual(10);
  });

  it('requires both names', () => {
    expect(() => usernamePermutations('', 'Smith')).toThrow();
    expect(() => usernamePermutations('John', '')).toThrow();
  });
});

describe('geo intel', () => {
  it('classifies private/loopback addresses without any network call', () => {
    expect(isPrivateIp('192.168.1.100')).toBe(true);
    expect(isPrivateIp('10.0.0.5')).toBe(true);
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('169.254.9.9')).toBe(true);
    expect(isPrivateIp('172.32.0.1')).toBe(false);
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('107.6.139.189')).toBe(false);
  });

  it('private IPs geolocate as LAN assets — honest no-public-geo result', async () => {
    const g = await ipGeo('192.168.1.100');
    expect(g.resolved).toBe(true);
    expect(g.privateLan).toBe(true);
    expect(g.note).toMatch(/private/i);
    expect(g.lat).toBeUndefined();
  });

  it('geocodeText caches per query (second call is instant, no network)', async () => {
    const first = await geocodeText('Brooklyn, New York');
    const t0 = Date.now();
    const second = await geocodeText('Brooklyn, New York');
    expect(second).toEqual(first);
    expect(Date.now() - t0).toBeLessThan(50);
  });
});

describe('dark web direct', () => {
  it('parses Ahmia result HTML into title/url/snippet records (fixture, no network)', async () => {
    const { parseAhmiaResults } = await import('../tools/osint.js');
    const fixture = `
      <li class="result first">
        <h4><a href="http://a2z5g7xrbqc3d5f7arbqc3d5f7arbqc3.onion/?id=1&amp;x=2">Searchable Onionservice One</a></h4>
        <p>First result snippet text.</p>
        <cite>http://a2z5g7xrbqc3d5f7arbqc3d5f7arbqc3.onion/?id=1&amp;x=2</cite>
      </li>
      <li class="result">
        <h4><a href="http://b2z5g7xrbqc3d5f7arbqc3d5f7arbqc3.onion/">Second Service</a></h4>
        <p>Second snippet.</p>
      </li>
      <li class="result">
        <h4><a href="http://a2z5g7xrbqc3d5f7arbqc3d5f7arbqc3.onion/?id=1&amp;x=2">Duplicate — should be skipped</a></h4>
      </li>
      <li class="result">
        <h4><a href="https://clearnet.example.com/not-onion">Not an onion — skipped</a></h4>
      </li>`;
    const results = parseAhmiaResults(fixture);
    expect(results.length).toBe(2);
    expect(results[0].title).toBe('Searchable Onionservice One');
    expect(results[0].url).toBe('http://a2z5g7xrbqc3d5f7arbqc3d5f7arbqc3.onion/?id=1&x=2');
    expect(results[0].snippet).toContain('First result snippet');
    expect(results[1].url).toContain('b2z5g7xrbqc3');
  });

  it('onionFetch rejects non-onion URLs before touching Tor', async () => {
    const { onionFetch } = await import('../tools/osint.js');
    await expect(onionFetch('https://example.com/clearnet')).rejects.toThrow(/not a \.onion/i);
  });
});

describe('identity corroboration', () => {
  it('matches subject names against profile display names', async () => {
    const { scoreIdentityMatch } = await import('../tools/osint.js');
    expect(scoreIdentityMatch({ name: 'Linus Torvalds' }, { displayName: 'Linus Torvalds' })).toBe('name-match');
    expect(scoreIdentityMatch({ name: 'Linus Torvalds' }, { displayName: 'Linus T.' })).toBe('name-mismatch'); // initial-only is ambiguous → never attributed to the subject
    expect(scoreIdentityMatch({ name: 'Linus Torvalds' }, { displayName: 'torvalds' })).toBe('name-match'); // last-name substring (handle-style)
    expect(scoreIdentityMatch({ name: 'Linus Torvalds' }, { displayName: 'bio: written by Linus Torvalds' })).toBe('name-match');
    expect(scoreIdentityMatch({ name: 'John Smith' }, { displayName: 'Alice Chains' })).toBe('name-mismatch');
    expect(scoreIdentityMatch({ name: 'John Smith' }, { displayName: 'JSmith Gaming' })).toBe('name-match'); // initials-style: carries the last name
    expect(scoreIdentityMatch({ name: 'Raul Glasgow' }, { displayName: 'Raul Gutierrez' })).toBe('name-mismatch'); // first-name-only overlap = DIFFERENT person
    expect(scoreIdentityMatch({ name: 'John Smith' }, null)).toBe('handle-only');
    expect(scoreIdentityMatch({}, { displayName: 'Linus Torvalds' })).toBe('handle-only'); // no hints, no claims
    expect(scoreIdentityMatch({ name: 'john smith' }, { displayName: '  John   Smith  ' })).toBe('name-match'); // normalization
  });
});

describe('search extraction', () => {
  it('extracts emails, phones and social URLs from search text', async () => {
    const { extractContacts } = await import('../tools/osint.js');
    const r = extractContacts(
      'Contact John Smith at john.smith83@gmail.com or call (718) 555-0142. ' +
      'See https://github.com/jsmith83 and https://t.me/jsmith83 — born 1985, year 2020 photo.png admin@example.com'
    );
    expect(r.emails).toContain('john.smith83@gmail.com');
    expect(r.emails.some((e) => e.includes('example.com'))).toBe(false); // decoy filtered
    expect(r.emails.some((e) => e.endsWith('.png'))).toBe(false);
    expect(r.phones).toContain('(718) 555-0142');
    expect(r.socialUrls.some((u) => u.includes('github.com/jsmith83'))).toBe(true);
    expect(r.socialUrls.some((u) => u.includes('t.me/jsmith83'))).toBe(true);
  });

  it('parses Bing SERP blocks into results (fixture)', async () => {
    const { parseBingResults } = await import('../tools/osint.js');
    const fixture = '<li class="b_algo"><h2><a href="https://example.org/profile">Profile Page</a></h2>' +
      '<p class="b_lineclamp">Snippet with (718) 555-0142 inside.</p></li>';
    const r = parseBingResults(fixture);
    expect(r.length).toBe(1);
    expect(r[0].title).toBe('Profile Page');
    expect(r[0].url).toBe('https://example.org/profile');
    expect(r[0].snippet).toContain('(718) 555-0142');
  });
});

describe('people records parsing', () => {
  it('parses FastPeopleSearch innerText into structured records (fixture)', async () => {
    const { parseFastPeopleSearch } = await import('../tools/osint.js');
    const fixture = [
      'FastPeopleSearch',
      '5 FREE public records found for Raul Glasgow.',
      'Raul Glasgow',
      'East Orange, NJ',
      'VIEW FREE DETAILS',
      'Raul Glasgow',
      'Age 54 \u2022 Brooklyn, NY',
      'Past Addresses: Brooklyn, NY \u2022 Newark, NJ \u2022 New York, NY',
      'Relatives: Cynthia Glasgow \u2022 Walter Lang',
      'AKA: Raul J Glasgow \u2022 Paul Glasgow',
      'VIEW FREE DETAILS',
    ].join('\n');
    const records = parseFastPeopleSearch(fixture, 'https://www.fastpeoplesearch.com/name/raul-glasgow');
    expect(records.length).toBe(2);
    expect(records[1].name).toBe('Raul Glasgow');
    expect(records[1].age).toBe(54);
    expect(records[1].city).toBe('Brooklyn, NY');
    expect(records[1].pastAddresses).toContain('Newark, NJ');
    expect(records[1].relatives).toContain('Cynthia Glasgow');
    expect(records[1].akas).toContain('Paul Glasgow');
    expect(records[1].sourceUrl).toContain('fastpeoplesearch.com');
  });
});

describe('person dorks', () => {
  it('builds engine + people-search links for every identifier kind', () => {
    const dorks = personDorks({ name: 'John Smith', email: 'john@example.com', username: 'jsmith', phone: '+17185550199', domain: 'example.com' });
    const labels = dorks.map((d) => d.label);
    expect(labels.some((l) => l.includes('Google: name'))).toBe(true);
    expect(labels.some((l) => l.includes('TruePeopleSearch'))).toBe(true);
    expect(labels.some((l) => l.includes('GitHub commits'))).toBe(true);
    expect(labels.some((l) => l.includes('Namechk'))).toBe(true);
    expect(labels.some((l) => l.includes('crt.sh'))).toBe(true);
    // Venmo lane is passive-only: search-engine index queries + the public profile URL.
    // No Venmo endpoint probing, no email→account enumeration.
    expect(labels.some((l) => l.includes('Venmo'))).toBe(true);
    const venmoIndexed = dorks.find((d) => d.label.includes('Venmo: indexed'));
    expect(venmoIndexed!.url).toContain('site%3Avenmo.com');
    const venmoProfile = dorks.find((d) => d.label.includes('Venmo: profile'));
    expect(venmoProfile!.url).toBe('https://venmo.com/u/jsmith');
    expect(dorks.every((d) => d.url.startsWith('https://'))).toBe(true);
  });
});
