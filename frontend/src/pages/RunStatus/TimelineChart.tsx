import { Callout, Card, Heading } from '@radix-ui/themes';
import {
  Chart as ChartJS,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
  type ChartOptions,
} from 'chart.js';
import annotationPlugin from 'chartjs-plugin-annotation';
import { useEffect, useRef } from 'react';
import { Line } from 'react-chartjs-2';
import type { RequestEntry, StepEventStatus, TimelineStatus } from '../../api/types';
import { formatTimeLabel } from './statusHelpers';
import {
  calculateMaxTime,
  computeBasisOffsetSeconds,
  convertDataStreamsToChartJs,
  createActivityDatasets,
  createChartAnnotations,
  extractActivityData,
  type ChartState,
} from './timelineChart';

ChartJS.register(LinearScale, PointElement, LineElement, Tooltip, Legend, annotationPlugin);

interface Props {
  timeline: TimelineStatus | null;
  stepStatus: Record<string, StepEventStatus> | null;
  requestHistory: RequestEntry[];
  timestampStart: string | null;
}

// Toggle visibility of the clicked legend item plus every unlabelled dataset sharing its
// colour (the activity strip stores each marker line as a separate same-colour dataset).
function activityLegendOnClick(
  this: unknown,
  _e: unknown,
  legendItem: { datasetIndex?: number },
  legend: { chart: ChartJS }
) {
  const index = legendItem.datasetIndex;
  if (index == null) return;
  const chart = legend.chart;
  // Chart.js uses meta.hidden === null to mean "inherit from the dataset"; toggling between
  // null and an explicit boolean is the documented legend pattern (its types omit the null).
  const meta = chart.getDatasetMeta(index) as { hidden: boolean | null };
  meta.hidden = meta.hidden === null ? !chart.data.datasets[index].hidden : null;

  const clickedColor = chart.data.datasets[index].borderColor;
  chart.data.datasets.forEach((dataset, i) => {
    if (i !== index && dataset.label === '' && dataset.borderColor === clickedColor) {
      (chart.getDatasetMeta(i) as { hidden: boolean | null }).hidden = meta.hidden;
    }
  });
  chart.update('none');
}

// The Timeline card: the main power-vs-time line chart with a "Now" marker and max/min watt
// annotations, plus a thin activity strip below marking request times and step completions.
// Recomputed from the polled RunnerStatus each render (10s); crop/now logic in timelineChart.ts.
export function TimelineChart({ timeline, stepStatus, requestHistory, timestampStart }: Props) {
  const mainRef = useRef<ChartJS<'line'> | null>(null);
  const activityRef = useRef<ChartJS<'line'> | null>(null);
  // Persisted x-axis max so the axis doesn't jitter each poll.
  const chartState = useRef<ChartState>({ currentMaxTime: null });

  // Sync the activity strip's left/right padding to the main chart's plot area so the two
  // x-axes line up exactly (the main chart's y-axis labels shift its plot area inward).
  useEffect(() => {
    const main = mainRef.current;
    const activity = activityRef.current;
    if (!main || !activity) return;
    const area = main.chartArea;
    if (!area) return;
    activity.options.layout = {
      padding: { left: area.left, right: main.width - area.right, top: 5, bottom: 5 },
    };
    activity.update('none');
  });

  if (!timestampStart) {
    return (
      <Card>
        <Heading as="h5" size="3" mb="1">
          Timeline
        </Heading>
        <Callout.Root color="blue">
          <Callout.Text>Timeline will appear when test starts</Callout.Text>
        </Callout.Root>
      </Card>
    );
  }

  const nowSeconds = (Date.now() - new Date(timestampStart).getTime()) / 1000;
  const basisOffsetSeconds = computeBasisOffsetSeconds(timeline, nowSeconds);
  const maxTime = calculateMaxTime(
    timeline,
    timestampStart,
    basisOffsetSeconds,
    chartState.current
  );

  const dataStreams = timeline?.data_streams || [];
  const datasets =
    dataStreams.length > 0 ? convertDataStreamsToChartJs(dataStreams, basisOffsetSeconds) : [];
  const annotations = createChartAnnotations(timeline, nowSeconds);

  const { stepCompletions, allRequests } = extractActivityData(
    stepStatus,
    requestHistory,
    timestampStart
  );
  const activityDatasets = createActivityDatasets(stepCompletions, allRequests);

  const sharedXScale = {
    type: 'linear' as const,
    min: basisOffsetSeconds,
    max: maxTime,
    ticks: {
      callback: (value: string | number) => formatTimeLabel(Math.floor(Number(value))),
      autoSkip: true,
      maxTicksLimit: 15,
    },
  };

  const mainOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: true,
    aspectRatio: 2.5,
    animation: false,
    layout: { padding: { left: 0, right: 15, top: 5, bottom: 5 } },
    interaction: { mode: 'index', intersect: false },
    plugins: {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      annotation: { common: { drawTime: 'beforeDraw' }, annotations } as any,
      legend: { display: datasets.length > 0 },
      tooltip: {
        callbacks: {
          title: (items) =>
            items.length ? formatTimeLabel(Math.floor(items[0].parsed.x ?? 0)) : '',
        },
      },
    },
    scales: {
      x: {
        ...sharedXScale,
        title: { display: true, text: 'Time' },
        grid: { display: true },
      },
      y: {
        title: { display: true, text: 'Watts' },
        grid: { color: (context) => (context.tick.value === 0 ? '#000000' : undefined) },
      },
    },
  };

  const activityOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: true,
    aspectRatio: 8,
    animation: false,
    layout: { padding: { left: 0, right: 15, top: 5, bottom: 5 } },
    plugins: {
      legend: {
        display: true,
        position: 'bottom',
        labels: { filter: (item) => item.text !== '' },
        onClick: activityLegendOnClick,
      },
      tooltip: { enabled: false },
    },
    scales: {
      x: { ...sharedXScale, display: false, grid: { display: false } },
      y: { display: false, min: 0, max: 1, grid: { display: false } },
    },
  };

  return (
    <Card>
      <Heading as="h5" size="3" mb="1">
        Timeline
      </Heading>
      <Line ref={mainRef} data={{ datasets }} options={mainOptions} />
      <div style={{ marginTop: 10 }}>
        <Line ref={activityRef} data={{ datasets: activityDatasets }} options={activityOptions} />
      </div>
    </Card>
  );
}
