import { describe, expect, it } from 'vitest';
import type { TimelineStatus } from '../src/api/types';
import {
  computeBasisOffsetSeconds,
  convertDataStreamsToChartJs,
  createActivityDatasets,
  createChartAnnotations,
  extractActivityData,
  parseOffsetSeconds,
} from '../src/pages/RunStatus/timelineChart';

// These guard the three timeline-crop fixes documented in the migration notes:
// the three offset regexes, and basisOffsetSeconds applied to every data x position
// (startX and nextStartX) so cropped long-running tests render in test-start coordinates.

describe('parseOffsetSeconds', () => {
  it('parses XmYs, Xm and Xs forms', () => {
    expect(parseOffsetSeconds('1m30s')).toBe(90);
    // The runner emits "Xm" (no seconds) for minute boundaries — must not map to 0.
    expect(parseOffsetSeconds('2m')).toBe(120);
    expect(parseOffsetSeconds('45s')).toBe(45);
    expect(parseOffsetSeconds('0s')).toBe(0);
    expect(parseOffsetSeconds('garbage')).toBe(0);
  });
});

describe('computeBasisOffsetSeconds', () => {
  it('shifts data by now-minus-crop, quantised to 20s', () => {
    // now is 1000s in; the crop window only reports the last 900s (now_offset "15m").
    const timeline = { now_offset: '15m' } as TimelineStatus;
    // 1000 - 900 = 100 → floor(100/20)*20 = 100
    expect(computeBasisOffsetSeconds(timeline, 1000)).toBe(100);
  });

  it('is zero when no crop is active (now_offset == now)', () => {
    const timeline = { now_offset: '1m0s' } as TimelineStatus;
    expect(computeBasisOffsetSeconds(timeline, 60)).toBe(0);
  });

  it('never goes negative', () => {
    const timeline = { now_offset: '15m' } as TimelineStatus;
    expect(computeBasisOffsetSeconds(timeline, 60)).toBe(0);
  });
});

describe('convertDataStreamsToChartJs', () => {
  it('expands points into 20s segments and applies the basis offset to start and next-start', () => {
    const datasets = convertDataStreamsToChartJs(
      [
        {
          label: 'Active Power',
          stepped: false,
          dashed: false,
          data: [
            { watts: 100, offset: '0s' },
            { watts: 200, offset: '0m20s' },
          ],
        },
      ],
      100
    );
    // Both the contiguous segment start and the carried next-start get +100 (the basis offset),
    // so the line stays connected in test-start coordinates rather than jumping back to 0.
    expect(datasets[0].data).toEqual([
      { x: 100, y: 100 },
      { x: 120, y: 100 },
      { x: 120, y: 200 },
      { x: 140, y: 200 },
    ]);
  });

  it('adds an explicit segment end when there is a gap to the next point', () => {
    const datasets = convertDataStreamsToChartJs(
      [
        {
          label: 'x',
          stepped: false,
          dashed: true,
          data: [
            { watts: 5, offset: '0s' },
            { watts: 9, offset: '1m0s' },
          ],
        },
      ],
      0
    );
    expect(datasets[0].borderDash).toEqual([5, 5]);
    expect(datasets[0].data).toEqual([
      { x: 0, y: 5 },
      { x: 20, y: 5 }, // gap (next starts at 60) → close the first segment at +20
      { x: 60, y: 9 },
      { x: 80, y: 9 },
    ]);
  });
});

describe('createChartAnnotations', () => {
  it('always includes the Now line and adds max/min lines when set_max_w is present', () => {
    const annotations = createChartAnnotations({ set_max_w: 5000 } as TimelineStatus, 42);
    const now = annotations[0] as { value: number; label: { content: string } };
    expect(now.value).toBe(42);
    expect(now.label.content).toBe('Now');
    const contents = annotations.map((a) => (a.label as { content: string }).content);
    expect(contents).toContain('setMaxW: 5000W');
    expect(contents).toContain('setMaxW: -5000W');
  });

  it('omits the max/min lines when set_max_w is null', () => {
    expect(createChartAnnotations({ set_max_w: null } as TimelineStatus, 0)).toHaveLength(1);
  });

  it('prefers the direction-specific device max and label over set_max_w when present', () => {
    const annotations = createChartAnnotations(
      {
        set_max_w: 5000,
        upper_max_w: 4000,
        upper_max_label: 'setMaxDischargeRateW',
        lower_max_w: 3000,
        lower_max_label: 'setMaxChargeRateW',
      } as TimelineStatus,
      0
    );
    const contents = annotations.map((a) => (a.label as { content: string }).content);
    expect(contents).toContain('setMaxDischargeRateW: 4000W');
    expect(contents).toContain('setMaxChargeRateW: -3000W');
  });
});

describe('activity strip', () => {
  it('extracts step completions and request markers relative to the start', () => {
    const start = '2025-01-01T00:00:00Z';
    const { stepCompletions, allRequests } = extractActivityData(
      { 'step-1': { started_at: start, completed_at: '2025-01-01T00:00:30Z', event_status: null } },
      [
        { timestamp: '2025-01-01T00:00:10Z' } as never,
        { timestamp: '2024-12-31T23:59:00Z' } as never, // before start → dropped
      ],
      start
    );
    expect(stepCompletions).toHaveLength(1);
    expect(stepCompletions[0].xPosition).toBe(30);
    expect(allRequests).toEqual([10]);
  });

  it('builds a legend dataset plus marker lines per request', () => {
    const datasets = createActivityDatasets([], [10, 20]);
    // One labelled "Requests" legend entry, then a marker line dataset per request.
    expect(datasets.filter((d) => d.label === 'Requests')).toHaveLength(1);
    expect(datasets.filter((d) => d.label === '').length).toBe(2);
  });
});
