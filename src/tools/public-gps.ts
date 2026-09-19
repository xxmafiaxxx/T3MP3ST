// =============================================================================
// PUBLIC GPS FEEDS — keyless open-geodata screen engine
// =============================================================================
// Aggregates PUBLIC environment/vehicle position broadcasts onto one map screen:
//   - Aircraft ADS-B positions (OpenSky Network anonymous API — public flight
//     broadcast data, the same feed aviation trackers render)
//   - USGS earthquakes (past 24h, global GeoJSON)
//   - NOAA active weather alerts (US, public NWS API)
//   - ISS live position (wheretheiss.at — the most public GPS point in orbit)
//   - OSM POIs around a pin (Overpass API — keyless OpenStreetMap data)
//   - Reverse geocoding for the operator's map pin (Nominatim /reverse)
// Every source is keyless. This layer maps VEHICLES, PHENOMENA and PLACES — it
// does not and will not resolve, fuse or track individual people. Person work
// stays in the OSINT Locator (public digital footprint) and nowhere else.

export interface GpsPoint {
  id: string;
  kind: 'aircraft' | 'quake' | 'alert' | 'iss' | 'poi';
  label: string;
  lat: number;
  lon: number;
  detail?: string;
}

export interface GpsFeed {
  source: string;
  fetchedAt: number;
  points: GpsPoint[];
  note?: string;
}

type FetchLike = (url: string, init?: Record<string, unknown>) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown>; text: () => Promise<string> }>;
const defaultFetch: FetchLike = (url, init) => fetch(url, init as never);

async function fetchJson<T>(url: string, opts: { fetcher?: FetchLike; timeoutMs?: number; headers?: Record<string, string>; method?: string; body?: string } = {}): Promise<T> {
  const f = opts.fetcher || defaultFetch;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 12_000);
  try {
    const r = await f(url, {
      method: opts.method || 'GET',
      headers: { ...(opts.headers || {}) },
      signal: ctrl.signal,
      ...(opts.body ? { body: opts.body } : {}),
    } as never);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return (await r.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

// --- bbox helpers -------------------------------------------------------------

export interface Bbox { lamin: number; lomin: number; lamax: number; lomax: number }

/** Parse + clamp an operator/browser-supplied bbox. Anonymous OpenSky is a shared
 *  free tier — spans are capped at 10° per axis so the screen stays a polite client. */
export function buildBbox(lamin: unknown, lomin: unknown, lamax: unknown, lomax: unknown): Bbox | null {
  const n = [lamin, lomin, lamax, lomax].map((v) => typeof v === 'number' ? v : parseFloat(String(v ?? '')));
  if (n.some((v) => !Number.isFinite(v))) return null;
  let [s, w, nn, e] = n;
  if (s > nn) [s, nn] = [nn, s];
  if (w > e) [w, e] = [e, w];
  s = Math.max(-90, Math.min(90, s)); nn = Math.max(-90, Math.min(90, nn));
  w = Math.max(-180, Math.min(180, w)); e = Math.max(-180, Math.min(180, e));
  if (nn - s > 10) nn = s + 10;
  if (e - w > 10) e = w + 10;
  if (nn - s < 0.01 || e - w < 0.01) return null;
  return { lamin: +s.toFixed(4), lomin: +w.toFixed(4), lamax: +nn.toFixed(4), lomax: +e.toFixed(4) };
}

export function bboxOverlaps(b: Bbox, lat: number, lon: number): boolean {
  return lat >= b.lamin && lat <= b.lamax && lon >= b.lomin && lon <= b.lomax;
}

// --- OpenSky aircraft (ADS-B broadcast) ----------------------------------------

// OpenSky state vector: [icao24, callsign, origin_country, time_position,
// last_contact, longitude, latitude, baro_altitude, on_ground, velocity,
// true_track, vertical_rate, sensors, geo_altitude, squawk, spi, position_source]
type OpenSkyState = (string | number | boolean | null | number[])[];

export function parseOpenSkyStates(states: OpenSkyState[], bbox?: Bbox, cap = 300): GpsPoint[] {
  const out: GpsPoint[] = [];
  for (const s of Array.isArray(states) ? states : []) {
    const lon = typeof s[5] === 'number' ? (s[5] as number) : null;
    const lat = typeof s[6] === 'number' ? (s[6] as number) : null;
    if (lat === null || lon === null || Number.isNaN(lat) || Number.isNaN(lon)) continue;
    if (bbox && !bboxOverlaps(bbox, lat, lon)) continue;
    const icao = String(s[0] || '').trim();
    const callsign = String(s[1] || '').trim() || icao;
    const country = String(s[2] || '').trim();
    const alt = typeof s[13] === 'number' ? (s[13] as number) : (typeof s[7] === 'number' ? (s[7] as number) : null);
    const vel = typeof s[9] === 'number' ? (s[9] as number) : null;
    const trk = typeof s[10] === 'number' ? (s[10] as number) : null;
    const onGround = s[8] === true;
    out.push({
      id: `aircraft:${icao}`,
      kind: 'aircraft',
      label: `✈ ${callsign}`,
      lat, lon,
      detail: [
        country ? `Origin: ${country}` : null,
        alt !== null ? `Alt: ${Math.round(alt)} m` : null,
        vel !== null ? `Speed: ${Math.round(vel * 3.6)} km/h` : null,
        trk !== null ? `Track: ${Math.round(trk)}°` : null,
        onGround ? 'ON GROUND' : 'airborne',
      ].filter(Boolean).join(' · '),
    });
    if (out.length >= cap) break;
  }
  return out;
}

interface OpenSkyResponse { time?: number; states?: OpenSkyState[] }

const aircraftCache = new Map<string, { at: number; feed: GpsFeed }>();

export async function fetchAircraft(bbox: Bbox, opts: { fetcher?: FetchLike; refresh?: boolean } = {}): Promise<GpsFeed> {
  const key = `${bbox.lamin},${bbox.lomin},${bbox.lamax},${bbox.lomax}`;
  const hit = aircraftCache.get(key);
  if (hit && !opts.refresh && Date.now() - hit.at < 45_000) return hit.feed;
  const url = `https://opensky-network.org/api/states/all?lamin=${bbox.lamin}&lomin=${bbox.lomin}&lamax=${bbox.lamax}&lomax=${bbox.lomax}`;
  try {
    const j = await fetchJson<OpenSkyResponse>(url, { fetcher: opts.fetcher, timeoutMs: 15_000 });
    const points = parseOpenSkyStates(j.states || [], bbox);
    const feed: GpsFeed = { source: 'OpenSky Network (ADS-B)', fetchedAt: Date.now(), points };
    aircraftCache.set(key, { at: Date.now(), feed });
    return feed;
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'network error';
    const note = /HTTP 429/.test(msg)
      ? 'rate-limited by OpenSky (shared anonymous tier) — retry in a minute'
      : /HTTP 50[23]/.test(msg) ? 'OpenSky temporarily unavailable' : `fetch failed: ${msg.slice(0, 80)}`;
    if (hit) return { ...hit.feed, note };
    return { source: 'OpenSky Network (ADS-B)', fetchedAt: Date.now(), points: [], note };
  }
}

// --- USGS earthquakes -----------------------------------------------------------

interface UsgsFeature { properties?: { mag?: number | null; place?: string | null; time?: number | null; url?: string | null }; geometry?: { coordinates?: [number, number, number] } }

export function parseUsgsQuakes(fc: { features?: UsgsFeature[] }, bbox?: Bbox, cap = 400): GpsPoint[] {
  const out: GpsPoint[] = [];
  for (const f of Array.isArray(fc.features) ? fc.features : []) {
    const c = f.geometry?.coordinates;
    if (!c || typeof c[0] !== 'number' || typeof c[1] !== 'number') continue;
    const [lon, lat, depth] = c;
    if (bbox && !bboxOverlaps(bbox, lat, lon)) continue;
    const mag = typeof f.properties?.mag === 'number' ? f.properties.mag : null;
    const when = typeof f.properties?.time === 'number' ? new Date(f.properties.time).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : null;
    out.push({
      id: `quake:${f.properties?.url || `${lat},${lon},${when}`}`,
      kind: 'quake',
      label: `🌍 M${mag !== null ? mag.toFixed(1) : '?'} ${f.properties?.place || 'unknown area'}`,
      lat, lon,
      detail: [when, depth !== undefined ? `Depth: ${Math.round(depth)} km` : null].filter(Boolean).join(' · '),
    });
    if (out.length >= cap) break;
  }
  return out;
}

const quakeCache = { at: 0, feed: null as GpsFeed | null };

export async function fetchEarthquakes(opts: { fetcher?: FetchLike; refresh?: boolean } = {}): Promise<GpsFeed> {
  if (quakeCache.feed && !opts.refresh && Date.now() - quakeCache.at < 120_000) return quakeCache.feed;
  try {
    const j = await fetchJson<{ features?: UsgsFeature[] }>(
      'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson',
      { fetcher: opts.fetcher, timeoutMs: 15_000 }
    );
    const feed: GpsFeed = { source: 'USGS (past 24h)', fetchedAt: Date.now(), points: parseUsgsQuakes(j) };
    quakeCache.at = Date.now(); quakeCache.feed = feed;
    return feed;
  } catch (e) {
    const note = `USGS feed unavailable: ${(e instanceof Error ? e.message : 'network error').slice(0, 80)}`;
    if (quakeCache.feed) return { ...quakeCache.feed, note };
    return { source: 'USGS (past 24h)', fetchedAt: Date.now(), points: [], note };
  }
}

// --- NOAA active weather alerts --------------------------------------------------

interface NoaaFeature { properties?: { event?: string; severity?: string; areaDesc?: string; headline?: string }; geometry?: unknown }

export function parseNoaaAlerts(fc: { features?: NoaaFeature[] }, bbox?: Bbox, cap = 200): GpsPoint[] {
  const out: GpsPoint[] = [];
  for (const f of Array.isArray(fc.features) ? fc.features : []) {
    const p = f.properties || {};
    const event = String(p.event || 'Weather alert');
    // NOAA alert geometry is a polygon (or zone refs without geometry). Polygon
    // centroids are cheap and good enough to place an alert pin on the map.
    const centroid = polygonCentroid(f.geometry);
    if (centroid) {
      if (bbox && !bboxOverlaps(bbox, centroid.lat, centroid.lon)) continue;
      out.push({
        id: `alert:${event}:${p.areaDesc || out.length}`,
        kind: 'alert',
        label: `⚠ ${event}`,
        lat: centroid.lat, lon: centroid.lon,
        detail: [p.severity, p.areaDesc, p.headline].filter(Boolean).join(' · ').slice(0, 300),
      });
    }
    if (out.length >= cap) break;
  }
  return out;
}

export function polygonCentroid(geom: unknown): { lat: number; lon: number } | null {
  const g = geom as { type?: string; coordinates?: unknown } | null | undefined;
  if (!g || typeof g.type !== 'string') return null;
  let rings: number[][][] = [];
  if (g.type === 'Polygon') rings = (g.coordinates as number[][][]) || [];
  else if (g.type === 'MultiPolygon') {
    for (const poly of ((g.coordinates as number[][][][]) || [])) rings.push(poly[0]);
  } else return null;
  let sx = 0, sy = 0, n = 0;
  for (const ring of rings) {
    for (const pt of ring || []) {
      if (!Array.isArray(pt) || typeof pt[0] !== 'number' || typeof pt[1] !== 'number') continue;
      sx += pt[0]; sy += pt[1]; n++;
    }
  }
  if (!n) return null;
  return { lon: +(sx / n).toFixed(4), lat: +(sy / n).toFixed(4) };
}

const alertsCache = { at: 0, feed: null as GpsFeed | null };

export async function fetchWeatherAlerts(opts: { fetcher?: FetchLike; refresh?: boolean } = {}): Promise<GpsFeed> {
  if (alertsCache.feed && !opts.refresh && Date.now() - alertsCache.at < 120_000) return alertsCache.feed;
  try {
    const j = await fetchJson<{ features?: NoaaFeature[] }>(
      'https://api.weather.gov/alerts/active?status=actual&message_type=alert&limit=500',
      { fetcher: opts.fetcher, timeoutMs: 15_000, headers: { 'user-agent': 'T3MP3ST-PublicGPS/1.0 (security testing platform)' } }
    );
    const feed: GpsFeed = { source: 'NOAA/NWS active alerts (US)', fetchedAt: Date.now(), points: parseNoaaAlerts(j) };
    alertsCache.at = Date.now(); alertsCache.feed = feed;
    return feed;
  } catch (e) {
    const note = `NWS feed unavailable: ${(e instanceof Error ? e.message : 'network error').slice(0, 80)}`;
    if (alertsCache.feed) return { ...alertsCache.feed, note };
    return { source: 'NOAA/NWS active alerts (US)', fetchedAt: Date.now(), points: [], note };
  }
}

// --- ISS live position -----------------------------------------------------------

interface IssResponse { latitude?: number; longitude?: number; altitude?: number; velocity?: number }

const issCache = { at: 0, feed: null as GpsFeed | null };

export async function fetchIss(opts: { fetcher?: FetchLike; refresh?: boolean } = {}): Promise<GpsFeed> {
  if (issCache.feed && !opts.refresh && Date.now() - issCache.at < 15_000) return issCache.feed;
  try {
    const j = await fetchJson<IssResponse>('https://api.wheretheiss.at/v1/satellites/25544', { fetcher: opts.fetcher, timeoutMs: 10_000 });
    if (typeof j.latitude !== 'number' || typeof j.longitude !== 'number') throw new Error('no position in response');
    const feed: GpsFeed = {
      source: 'wheretheiss.at',
      fetchedAt: Date.now(),
      points: [{
        id: 'iss', kind: 'iss',
        label: '🛰 ISS (Zarya)',
        lat: j.latitude, lon: j.longitude,
        detail: [
          j.altitude !== undefined ? `Alt: ${Math.round(j.altitude)} km` : null,
          j.velocity !== undefined ? `${Math.round(j.velocity)} km/h` : null,
        ].filter(Boolean).join(' · '),
      }],
    };
    issCache.at = Date.now(); issCache.feed = feed;
    return feed;
  } catch (e) {
    const note = `ISS feed unavailable: ${(e instanceof Error ? e.message : 'network error').slice(0, 80)}`;
    if (issCache.feed) return { ...issCache.feed, note };
    return { source: 'wheretheiss.at', fetchedAt: Date.now(), points: [], note };
  }
}

// --- Reverse geocoding (pin → place name, Nominatim) ------------------------------

interface NominatimReverse { display_name?: string; address?: Record<string, string>; type?: string }

const reverseCache = new Map<string, { label: string; address: Record<string, string> } | null>();
const reverseLastCall = { at: 0 };

/** Nominatim /reverse for the operator's own map pin. 1 req/s throttle + process-
 *  lifetime cache per the usage policy. Returns null (cached) when nothing resolves. */
export async function reverseGeocode(lat: number, lon: number, opts: { fetcher?: FetchLike } = {}): Promise<{ label: string; address: Record<string, string> } | null> {
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
  const key = `${lat.toFixed(4)},${lon.toFixed(4)}`;
  if (reverseCache.has(key)) return reverseCache.get(key) ?? null;
  const wait = 1100 - (Date.now() - reverseLastCall.at);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  reverseLastCall.at = Date.now();
  try {
    const j = await fetchJson<NominatimReverse>(
      `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lon}&format=jsonv2&zoom=14`,
      { fetcher: opts.fetcher, timeoutMs: 10_000, headers: { 'user-agent': 'T3MP3ST-PublicGPS/1.0 (security testing platform)' } }
    );
    const hit = j.display_name ? { label: j.display_name, address: j.address || {} } : null;
    reverseCache.set(key, hit);
    return hit;
  } catch {
    reverseCache.set(key, null);
    return null;
  }
}

// --- OSM POIs around the pin (Overpass) --------------------------------------------

export const POI_KINDS = ['cafe', 'restaurant', 'fuel', 'hospital', 'pharmacy', 'police', 'bank', 'hotel', 'school', 'place_of_worship'] as const;
export type PoiKind = (typeof POI_KINDS)[number];

export function isPoiKind(k: unknown): k is PoiKind {
  return typeof k === 'string' && (POI_KINDS as readonly string[]).includes(k);
}

export function overpassQuery(lat: number, lon: number, radiusM: number, kind: PoiKind): string {
  const r = Math.max(50, Math.min(2000, Math.round(radiusM || 500)));
  return `[out:json][timeout:20];node(around:${r},${lat},${lon})[amenity=${kind}];out 50;`;
}

interface OverpassElement { type?: string; id?: number; lat?: number; lon?: number; tags?: { name?: string; [k: string]: string | undefined } }

const poiCache = new Map<string, { at: number; feed: GpsFeed }>();
const poiLastCall = { at: 0 };

export async function fetchPois(lat: number, lon: number, radiusM: number, kind: PoiKind, opts: { fetcher?: FetchLike; refresh?: boolean } = {}): Promise<GpsFeed> {
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return { source: 'OpenStreetMap (Overpass)', fetchedAt: Date.now(), points: [], note: 'invalid pin coordinates' };
  const key = `${lat.toFixed(4)},${lon.toFixed(4)},${Math.round(radiusM)},${kind}`;
  const hit = poiCache.get(key);
  if (hit && !opts.refresh && Date.now() - hit.at < 600_000) return hit.feed;
  // Overpass etiquette: space out calls a few seconds.
  const wait = 3000 - (Date.now() - poiLastCall.at);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  poiLastCall.at = Date.now();
  try {
    const f = opts.fetcher || defaultFetch;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 25_000);
    let json: { elements?: OverpassElement[] };
    try {
      const r = await f('https://overpass-api.de/api/interpreter', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'T3MP3ST-PublicGPS/1.0' },
        body: `data=${encodeURIComponent(overpassQuery(lat, lon, radiusM, kind))}`,
        signal: ctrl.signal,
      } as never);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      json = (await r.json()) as { elements?: OverpassElement[] };
    } finally {
      clearTimeout(timer);
    }
    const points: GpsPoint[] = [];
    for (const el of Array.isArray(json.elements) ? json.elements : []) {
      if (typeof el.lat !== 'number' || typeof el.lon !== 'number') continue;
      const name = el.tags?.name || `(unnamed ${kind})`;
      const extras = Object.entries(el.tags || {})
        .filter(([k, v]) => v && k !== 'name' && !k.startsWith('name:') && k !== 'amenity')
        .slice(0, 4).map(([k, v]) => `${k}: ${v}`);
      points.push({
        id: `poi:${el.type}:${el.id}`,
        kind: 'poi',
        label: `🍴 ${name}`,
        lat: el.lat, lon: el.lon,
        detail: extras.join(' · ') || kind.replace(/_/g, ' '),
      });
      if (points.length >= 50) break;
    }
    const feed: GpsFeed = { source: 'OpenStreetMap (Overpass)', fetchedAt: Date.now(), points };
    poiCache.set(key, { at: Date.now(), feed });
    return feed;
  } catch (e) {
    const note = `Overpass unavailable: ${(e instanceof Error ? e.message : 'network error').slice(0, 80)}`;
    if (hit) return { ...hit.feed, note };
    return { source: 'OpenStreetMap (Overpass)', fetchedAt: Date.now(), points: [], note };
  }
}

// --- Operator pin → nearest public infrastructure context --------------------------
// Purely informational: names the OSM place at the pin and (for IPv4 pins) the
// reverse-resolved hostname. Gives the operator quick context for a map point.

export async function pinContext(lat: number, lon: number): Promise<{ label: string | null; note?: string }> {
  const rev = await reverseGeocode(lat, lon);
  if (rev) return { label: rev.label };
  return { label: null, note: 'no OSM place at this point' };
}
