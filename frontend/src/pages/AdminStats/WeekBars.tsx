import { Box, Flex, Text } from '@radix-ui/themes';
import { IconCalendar } from '@tabler/icons-react';
import type { RunsPerWeekGranularity, WeekBar } from '../../api/types';
import { SectionCard } from '../../components/SectionCard';

const GRANULARITY_TITLE: Record<RunsPerWeekGranularity, string> = {
  week: 'Tests Per Week',
  fortnight: 'Tests Per Fortnight',
  month: 'Tests Per Month',
};

const CHART_HEIGHT = 80;
const BAR_MAX_WIDTH = 20;
const AXIS_WIDTH = 28;
// Cap on visible x-axis labels
const MAX_LABELS = 12;

// Denser than plain 1/2/5 so the axis max stays within ~20% of the real max.
const NICE_STEPS = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];

function niceMax(value: number): number {
  if (value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const normalized = value / magnitude;
  const step = NICE_STEPS.find((s) => normalized <= s) ?? 10;
  return step * magnitude;
}

// Label month/year-boundary bars, thinned to MAX_LABELS if there are more.
function labelIndices(bars: WeekBar[]): Set<number> {
  const candidates = bars.reduce<number[]>((acc, bar, i) => {
    if (bar.month) acc.push(i);
    return acc;
  }, []);
  if (candidates.length <= MAX_LABELS) return new Set(candidates);
  const stride = Math.ceil(candidates.length / MAX_LABELS);
  return new Set(candidates.filter((_, idx) => idx % stride === 0));
}

export function WeekBars({ bars, granularity }: { bars: WeekBar[]; granularity: RunsPerWeekGranularity }) {
  if (bars.length === 0) return null;
  const rawMax = Math.max(...bars.map((b) => b.count), 1);
  const axisMax = niceMax(rawMax);
  const ticks = [axisMax, axisMax / 2, 0];
  const shownLabels = labelIndices(bars);

  return (
    <SectionCard title={GRANULARITY_TITLE[granularity]} icon={<IconCalendar size={16} />}>
      <Flex gap="2">
        <Flex
          direction="column"
          justify="between"
          align="end"
          style={{ height: CHART_HEIGHT, width: AXIS_WIDTH, flexShrink: 0 }}
        >
          {ticks.map((tick, i) => (
            <Text key={i} color="gray" style={{ fontSize: '0.6rem', fontVariantNumeric: 'tabular-nums' }}>
              {Math.round(tick)}
            </Text>
          ))}
        </Flex>
        <Box style={{ position: 'relative', flex: 1, minWidth: 0, height: CHART_HEIGHT }}>
          <Flex
            direction="column"
            justify="between"
            style={{ position: 'absolute', inset: 0 }}
          >
            {ticks.map((_, i) => (
              <Box key={i} style={{ borderTop: '1px solid var(--gray-a5)' }} />
            ))}
          </Flex>
          <Flex align="end" gap="1" style={{ position: 'absolute', inset: 0 }}>
            {bars.map((bar, i) => (
              <Flex key={i} justify="center" align="end" style={{ flex: 1, minWidth: 0, height: '100%' }}>
                <Box
                  title={`${bar.month || ''} ${bar.year || ''}: ${bar.count} runs`.trim()}
                  style={{
                    width: '100%',
                    maxWidth: BAR_MAX_WIDTH,
                    backgroundColor: 'var(--green-9)',
                    borderRadius: '4px 4px 0 0',
                    height: Math.max(2, Math.round((bar.count / axisMax) * CHART_HEIGHT)),
                  }}
                />
              </Flex>
            ))}
          </Flex>
        </Box>
      </Flex>
      <Flex gap="1" mt="1" style={{ paddingLeft: AXIS_WIDTH + 8 }}>
        {bars.map((bar, i) => (
          <Box key={i} style={{ flex: 1, minWidth: 0, position: 'relative' }}>
            {shownLabels.has(i) && (
              <Text
                color="gray"
                align="center"
                style={{
                  fontSize: '0.6rem',
                  whiteSpace: 'nowrap',
                  position: 'absolute',
                  left: '50%',
                  transform: 'translateX(-50%)',
                }}
              >
                {[bar.month, bar.year].filter(Boolean).join(' ')}
              </Text>
            )}
          </Box>
        ))}
      </Flex>
    </SectionCard>
  );
}
