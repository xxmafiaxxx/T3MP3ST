import { describe, it, expect } from 'vitest';
import {
  buildBbox,
  bboxOverlaps,
  parseOpenSkyStates,
  parseUsgsQuakes,
  parseNoaaAlerts,
  polygonCentroid,
  overpassQuery,
  isPoiKind,
  reverseGeocode,
  fetchAircraft,
  fetchIss,
} from '../tools/public-gps.js';

// ── fixtures ─────────────────────────────────────────────────────────────────

const SKY_STATES = [
  ['abc123', 'UAL123  ', 'United States', 1700000000, 1700000000, -73.97, 40.7, 10000, false, 230, 95, 0, null, 10500, '1200', false, 0],
  ['def456', null, 'Germany', 1700000000, 1700000000, 13.4, 52.5, null, true, null, null, null, null, null, null, false, 1],
  ['ghi789', 'NOPOS ', 'Unknown', 1700000000, 1700000000, null, null, null, false, null, null, null, null, null, null, false, 0], // no position → skipped
];

const USGS_FC = {
  features: [
    { properties: { mag: 4.6, place: '123 km SSE of somewhere', time: 1700000000000, url: 'usgs-x' }, geometry: { coordinates: [145.1, 12.3, 35.2] } },
    { properties: { mag: null, place: null, time: null }, geometry: { coordinates: [0, 0, 10] } },
    { properties: { mag: 2.1 }, geometry: { coordinates: null } }, // no coords → skipped
  ],
};

const NOAA_FC = {
  features: [
    {
      properties: { event: 'Tornado Warning', severity: 'Extreme', areaDesc: 'Some County, TX', headline: 'Radar-confirmed tornado' },
      geometry: { type: 'Polygon', coordinates: [[[-100, 32], [-99, 32], [-99, 33], [-100, 33], [-100, 32]]] },
    },
    { properties: { event: 'Flood Advisory' }, geometry: null }, // no geometry → no pin
  ],
};

const ok = (body: unknown, status = 200) => async () => ({ ok: true, status, json: async () => body, text: async () => JSON.stringify(body) });

// ── bbox ──────────────────────────────────────────────────────────────────────

describe('buildBbox', () => {
  it('normalizes swapped corners and clamps to a 10° span (polite anonymous-tier client)', () => {
    expect(buildBbox(50, 20, 40, 10)).toEqual({ lamin: 40, lomin: 10, lamax: 50, lomax: 20 });
    const big = buildBbox(-80, -170, 80, 170)!;
    expect(big.lamax - big.lamin).toBeLessThanOrEqual(10);
    expect(big.lomax - big.lomin).toBeLessThanOrEqual(10);
  });

  it('rejects non-numeric and degenerate boxes', () => {
    expect(buildBbox('x', 0, 1, 1)).toBeNull();
    expect(buildBbox(40, -73, 40.0001, -73.0001)).toBeNull(); // span < 0.01°
  });

  it('bboxOverlaps membership works', () => {
    const b = buildBbox(40, -74, 41, -73)!;
    expect(bboxOverlaps(b, 40.5, -73.5)).toBe(true);
    expect(bboxOverlaps(b, 42, -73.5)).toBe(false);
  });
});

// ── parsers ───────────────────────────────────────────────────────────────────

describe('parseOpenSkyStates', () => {
  it('maps positioned states, trims callsigns, skips positionless rows', () => {
    const pts = parseOpenSkyStates(SKY_STATES);
    expect(pts).toHaveLength(2);
    expect(pts[0].label).toBe('✈ UAL123');
    expect(pts[0].detail).toContain('airborne');
    expect(pts[1].label).toBe('✈ def456'); // null callsign falls back to icao24
    expect(pts[1].detail).toContain('ON GROUND');
  });

  it('filters by bbox and caps the point count', () => {
    const b = buildBbox(40, -74, 41, -73)!;
    expect(parseOpenSkyStates(SKY_STATES, b).map((p) => p.id)).toEqual(['aircraft:abc123']);
    expect(parseOpenSkyStates(SKY_STATES, undefined, 1)).toHaveLength(1);
  });
});

describe('parseUsgsQuakes', () => {
  it('maps geojson features to quake points with mag/place/depth', () => {
    const pts = parseUsgsQuakes(USGS_FC);
    expect(pts).toHaveLength(2);
    expect(pts[0].label).toContain('M4.6');
    expect(pts[0].detail).toContain('Depth: 35 km');
    expect(pts[0].id).toBe('quake:usgs-x');
  });
});

describe('parseNoaaAlerts + polygonCentroid', () => {
  it('centroids polygons into alert pins and drops geometryless alerts', () => {
    const pts = parseNoaaAlerts(NOAA_FC);
    expect(pts).toHaveLength(1);
    expect(pts[0].label).toBe('⚠ Tornado Warning');
    expect(pts[0].lat).toBeCloseTo(32.5);
    expect(pts[0].lon).toBeCloseTo(-99.5);
    expect(pts[0].detail).toContain('Extreme');
  });

  it('polygonCentroid handles MultiPolygon and rejects junk', () => {
    const multi = polygonCentroid({ type: 'MultiPolygon', coordinates: [[[[0, 0], [2, 0], [2, 2], [0, 2], [0, 0]]]] });
    expect(multi).toEqual({ lon: 1, lat: 1 });
    expect(polygonCentroid({ type: 'Point', coordinates: [1, 2] })).toBeNull();
    expect(polygonCentroid(null)).toBeNull();
  });
});

// ── network functions (stubbed fetch) ─────────────────────────────────────────

describe('feed functions with injected fetcher', () => {
  it('fetchAircraft parses OpenSky payloads and reports honest rate-limit notes', async () => {
    const feed = await fetchAircraft(buildBbox(40, -74, 41, -73)!, { fetcher: ok({ states: SKY_STATES }), refresh: true });
    expect(feed.points).toHaveLength(2);
    expect(feed.source).toContain('OpenSky');
    const rl = await fetchAircraft(buildBbox(40, -74, 41, -73)!, {
      fetcher: async () => ({ ok: false, status: 429, json: async () => ({}), text: async () => '' }),
      refresh: true,
    });
    expect(rl.note).toContain('rate-limited');
  });

  it('fetchIss rejects positionless payloads with a note, serves cache after success', async () => {
    const bad = await fetchIss({ fetcher: ok({ latitude: 'x' }), refresh: true });
    expect(bad.points).toHaveLength(0);
    expect(bad.note).toContain('unavailable');
    let calls = 0;
    const good = await fetchIss({
      fetcher: async () => { calls++; return { ok: true, status: 200, json: async () => ({ latitude: 10.5, longitude: 20.5, altitude: 420, velocity: 27600 }), text: async () => '' }; },
      refresh: true,
    });
    expect(good.points[0].label).toBe('🛰 ISS (Zarya)');
    const cached = await fetchIss({ fetcher: async () => { calls++; throw new Error('should not be called'); } });
    expect(cached.points[0].lat).toBe(10.5);
    expect(calls).toBe(1);
  });
});

// ── POI query builder + kinds ─────────────────────────────────────────────────

describe('overpassQuery / isPoiKind', () => {
  it('builds a bounded around() query and clamps radius', () => {
    expect(overpassQuery(40.7, -73.97, 500, 'cafe')).toContain('node(around:500,40.7,-73.97)[amenity=cafe]');
    expect(overpassQuery(40.7, -73.97, 99999, 'fuel')).toContain('node(around:2000');
    expect(overpassQuery(40.7, -73.97, 1, 'police')).toContain('node(around:50');
    expect(overpassQuery(40.7, -73.97, 500, 'school')).toContain('out 50;');
  });

  it('whitelists POI kinds', () => {
    expect(isPoiKind('cafe')).toBe(true);
    expect(isPoiKind('place_of_worship')).toBe(true);
    expect(isPoiKind('brothel')).toBe(false);
    expect(isPoiKind(undefined)).toBe(false);
  });
});

// ── reverse geocode (throttle + cache) ────────────────────────────────────────

describe('reverseGeocode', () => {
  it('caches per-rounded-coords: second call is instant and does not refetch', async () => {
    let calls = 0;
    const fetcher = ok({ display_name: '1 Test Street, Testville', address: { house_number: '1' } });
    const counted = async (url: string) => { calls++; return fetcher(url); };
    const a = await reverseGeocode(40.71234, -73.98765, { fetcher: counted });
    const b = await reverseGeocode(40.71234, -73.98765, { fetcher: counted });
    const c = await reverseGeocode(40.71235, -73.98765, { fetcher: counted }); // 5th decimal differs → same cache key after rounding? no: toFixed(4) differs
    expect(a?.label).toBe('1 Test Street, Testville');
    expect(b?.label).toBe('1 Test Street, Testville');
    expect(calls).toBe(c === null ? 2 : 3); // distinct 4-decimal key may fetch once more
    expect(calls).toBeLessThan(4);
  }, 10_000);

  it('caches null results and rejects invalid coordinates without fetching', async () => {
    let calls = 0;
    const counted = async () => { calls++; throw new Error('down'); };
    expect(await reverseGeocode(10, 20, { fetcher: counted })).toBeNull();
    expect(await reverseGeocode(10, 20, { fetcher: counted })).toBeNull(); // null cached
    expect(await reverseGeocode(999, 999, { fetcher: counted })).toBeNull(); // invalid, no fetch
    expect(calls).toBe(1);
  }, 10_000);
});
