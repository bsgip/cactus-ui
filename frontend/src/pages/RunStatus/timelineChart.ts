import type {
  TimelineDataStreamEntry,
  TimelineStatus,
  StepEventStatus,
  RequestEntry,
} from '../../api/types';

// Timeline chart geometry. Note the crop/now handling: parseOffsetSeconds parses the offset
// regexes and basisOffsetSeconds is applied to all data x positions (including nextStartX) so
// long-running tests with a crop stay aligned.

export const CHART_CONFIG = {
  RIGHT_BUFFER_SECONDS: 90, // How much empty space on the right
  RESIZE_THRESHOLD: 0.8, // Resize when 'now' reaches 80% of visible range
  MIN_VISIBLE_TIME: 120, // Minimum time window to show (2 minutes)
};

const STEP_COLORS = [
  '#1f77b4',
  '#ff7f0e',
  '#2ca02c',
  '#d62728',
  '#9467bd',
  '#8c564b',
  '#e377c2',
  '#7f7f7f',
  '#bcbd22',
  '#17becf',
  '#393b79',
  '#637939',
  '#8c6d31',
  '#843c39',
  '#7b4173',
  '#5254a3',
  '#8ca252',
  '#bd9e39',
  '#ad494a',
  '#a55194',
];

export function getStepColor(index: number): string {
  return STEP_COLORS[index % STEP_COLORS.length];
}

// Parse a duration_to_label offset ("XmYs" / "Xm" / "Xs") to seconds. The runner emits
// "Xm" (no seconds) for minute-boundary offsets, so all three forms must be handled.
export function parseOffsetSeconds(offsetStr: string): number {
  const minsSecs = offsetStr.match(/^(\d+)m(\d+)s$/);
  if (minsSecs) return parseInt(minsSecs[1]) * 60 + parseInt(minsSecs[2]);
  const mins = offsetStr.match(/^(\d+)m$/);
  if (mins) return parseInt(mins[1]) * 60;
  const secs = offsetStr.match(/^(\d+)s$/);
  if (secs) return parseInt(secs[1]);
  return 0;
}

export interface XyPoint {
  x: number;
  y: number | null;
}

export interface TimelineDataset {
  label: string;
  data: XyPoint[];
  borderColor: string;
  backgroundColor: string;
  borderDash?: number[];
  tension: number;
  spanGaps: boolean;
}

// Persisted across polls (a useRef). Lets the x-axis max stay stable between updates and only
// jump ahead when 'now' nears the right edge or data overruns.
export interface ChartState {
  currentMaxTime: number | null;
}

export function calculateMaxTime(
  timeline: TimelineStatus | null,
  timelineStart: string | null,
  basisOffsetSeconds: number,
  state: ChartState
): number {
  if (!timelineStart) {
    return CHART_CONFIG.MIN_VISIBLE_TIME;
  }

  const nowSeconds = (Date.now() - new Date(timelineStart).getTime()) / 1000;
  let maxDataTime = nowSeconds;

  timeline?.data_streams?.forEach((stream) => {
    stream.data.forEach((point) => {
      maxDataTime = Math.max(
        maxDataTime,
        parseOffsetSeconds(point.offset) + basisOffsetSeconds + 20
      );
    });
  });

  const currentMax =
    state.currentMaxTime || Math.max(maxDataTime, nowSeconds) + CHART_CONFIG.RIGHT_BUFFER_SECONDS;

  const visibleRange = currentMax;
  const nowPosition = nowSeconds / visibleRange;

  const shouldResize = nowPosition > CHART_CONFIG.RESIZE_THRESHOLD || maxDataTime > currentMax - 20;

  if (shouldResize) {
    const newMax = Math.max(maxDataTime, nowSeconds) + CHART_CONFIG.RIGHT_BUFFER_SECONDS;
    state.currentMaxTime = newMax;
    return newMax;
  }

  return currentMax;
}

export function convertDataStreamsToChartJs(
  dataStreams: TimelineDataStreamEntry[],
  basisOffsetSeconds: number
): TimelineDataset[] {
  // Colour each stream deterministically by its label (not array position) so a given series
  // keeps the same colour across polls regardless of how many streams the runner reports, and
  // so every visible stream is distinct. Labels are sorted to give a stable palette index.
  const orderedLabels = [...new Set(dataStreams.map((ds) => ds.label))].sort();

  return dataStreams.map((ds) => {
    const sortedData = [...ds.data].sort(
      (a, b) => parseOffsetSeconds(a.offset) - parseOffsetSeconds(b.offset)
    );
    // Each point is stored as a 20s interval
    const expandedData: XyPoint[] = [];
    sortedData.forEach((point, index) => {
      const startX = parseOffsetSeconds(point.offset) + basisOffsetSeconds;
      const endX = startX + 20;

      expandedData.push({ x: startX, y: point.watts });

      if (index < sortedData.length - 1) {
        const nextStartX = parseOffsetSeconds(sortedData[index + 1].offset) + basisOffsetSeconds;
        // Add an end point only when there's a gap to the next segment; otherwise carry the
        // value to where the next segment begins so contiguous segments stay connected.
        if (nextStartX > endX) {
          expandedData.push({ x: endX, y: point.watts });
        } else {
          expandedData.push({ x: nextStartX, y: point.watts });
        }
      } else {
        expandedData.push({ x: endX, y: point.watts });
      }
    });

    const color = getStepColor(orderedLabels.indexOf(ds.label));
    return {
      label: ds.label,
      data: expandedData,
      borderColor: color,
      backgroundColor: color,
      borderDash: ds.dashed ? [5, 5] : undefined,
      tension: 0,
      spanGaps: false,
    };
  });
}

// chartjs-plugin-annotation annotation objects. Loosely typed because the plugin's option
// shape is broad.
export function createChartAnnotations(
  timeline: TimelineStatus | null,
  nowSeconds: number
): Record<string, unknown>[] {
  const annotations: Record<string, unknown>[] = [
    {
      type: 'line',
      borderColor: 'black',
      borderWidth: 2,
      label: {
        display: true,
        content: 'Now',
        position: 'start',
        backgroundColor: 'rgba(0,0,0,0.8)',
        color: 'white',
      },
      scaleID: 'x',
      value: nowSeconds,
    },
  ];

  // Prefer the direction-specific device max (accounts for asymmetric setMaxDischargeRateW /
  // setMaxChargeRateW); fall back to the flat setMaxW for older runners that don't send them.
  const upperMaxW = timeline?.upper_max_w ?? timeline?.set_max_w ?? null;
  const upperMaxLabel = timeline?.upper_max_w != null ? timeline.upper_max_label : 'setMaxW';
  const lowerMaxW = timeline?.lower_max_w ?? timeline?.set_max_w ?? null;
  const lowerMaxLabel = timeline?.lower_max_w != null ? timeline.lower_max_label : 'setMaxW';

  if (upperMaxW != null) {
    annotations.push({
      type: 'line',
      borderColor: 'black',
      borderWidth: 3,
      borderDash: [5, 5],
      scaleID: 'y',
      value: upperMaxW,
      label: {
        display: true,
        content: `${upperMaxLabel ?? 'Device max'}: ${upperMaxW}W`,
        position: 'end',
      },
    });
  }
  if (lowerMaxW != null) {
    annotations.push({
      type: 'line',
      borderColor: 'black',
      borderWidth: 3,
      borderDash: [5, 5],
      scaleID: 'y',
      value: -lowerMaxW,
      label: {
        display: true,
        content: `${lowerMaxLabel ?? 'Device max'}: -${lowerMaxW}W`,
        position: 'end',
      },
    });
  }

  return annotations;
}

interface StepCompletion {
  stepName: string;
  xPosition: number;
  color: string;
}

export function extractActivityData(
  stepStatus: Record<string, StepEventStatus> | null,
  requestHistory: RequestEntry[],
  timelineStart: string | null
): { stepCompletions: StepCompletion[]; allRequests: number[] } {
  if (!timelineStart) return { stepCompletions: [], allRequests: [] };

  const start = new Date(timelineStart).getTime();
  const stepCompletions: StepCompletion[] = [];
  const allRequests: number[] = [];

  Object.entries(stepStatus || {}).forEach(([stepName, stepInfo], idx) => {
    if (stepInfo.completed_at) {
      const timeOffset = (new Date(stepInfo.completed_at).getTime() - start) / 1000;
      if (timeOffset >= 0) {
        stepCompletions.push({ stepName, xPosition: timeOffset, color: getStepColor(idx) });
      }
    }
  });

  (requestHistory || []).forEach((req) => {
    const timeOffset = (new Date(req.timestamp).getTime() - start) / 1000;
    if (timeOffset >= 0) {
      allRequests.push(timeOffset);
    }
  });

  return { stepCompletions, allRequests };
}

export interface ActivityDataset {
  label: string;
  data: XyPoint[];
  borderColor: string;
  borderWidth: number;
  pointRadius: number;
  showLine?: boolean;
  tension?: number;
}

export function createActivityDatasets(
  stepCompletions: StepCompletion[],
  allRequests: number[]
): ActivityDataset[] {
  const datasets: ActivityDataset[] = [];

  // Add step completions first (for legend order, but drawn last so they sit on top).
  const stepLegendAdded = new Set<string>();
  const completionLines: ActivityDataset[] = [];

  stepCompletions.forEach((completion) => {
    if (!stepLegendAdded.has(completion.stepName)) {
      stepLegendAdded.add(completion.stepName);
      datasets.push({
        label: `${completion.stepName} (completed)`,
        data: [],
        borderColor: completion.color,
        borderWidth: 4,
        pointRadius: 0,
      });
    }

    completionLines.push({
      label: '',
      data: [
        { x: completion.xPosition, y: 0.2 },
        { x: completion.xPosition, y: 0.8 },
      ],
      borderColor: completion.color,
      borderWidth: 4,
      pointRadius: 0,
      showLine: true,
      tension: 0,
    });
  });

  if (allRequests.length > 0) {
    datasets.push({
      label: 'Requests',
      data: [],
      borderColor: 'rgba(128, 128, 128, 0.4)',
      borderWidth: 2,
      pointRadius: 0,
    });

    allRequests.forEach((xPos) => {
      datasets.push({
        label: '',
        data: [
          { x: xPos, y: 0.2 },
          { x: xPos, y: 0.8 },
        ],
        borderColor: 'rgba(128, 128, 128, 0.4)',
        borderWidth: 2,
        pointRadius: 0,
        showLine: true,
        tension: 0,
      });
    });
  }

  datasets.push(...completionLines);
  return datasets;
}

// nowOffsetSeconds is quantised to 20s intervals by the runner, so subtract and re-floor to
// avoid a fractional remainder (e.g. 8s) appearing as the axis min when no crop is active.
export function computeBasisOffsetSeconds(
  timeline: TimelineStatus | null,
  nowSeconds: number
): number {
  const nowOffsetSeconds = timeline?.now_offset ? parseOffsetSeconds(timeline.now_offset) : 0;
  return Math.floor(Math.max(0, nowSeconds - nowOffsetSeconds) / 20) * 20;
}
