import { Box, Flex, Text } from '@mantine/core';
import type { WeekBar } from '../../api/types';
import { SectionCard } from '../../components/SectionCard';

export function WeekBars({ bars }: { bars: WeekBar[] }) {
  if (bars.length === 0) return null;
  const maxCount = Math.max(...bars.map((b) => b.count), 1);

  return (
    <SectionCard title="Tests Per Week">
      <Flex align="flex-end" gap={2} h={110}>
        {bars.map((bar, i) => (
          <Flex key={i} direction="column" align="center" style={{ flex: 1, minWidth: 0 }}>
            <Text fz="0.6rem" c="dimmed">
              {bar.count}
            </Text>
            <Box
              title={`${bar.month || ''} ${bar.year || ''}: ${bar.count} runs`.trim()}
              bg="green.6"
              w="100%"
              style={{ height: Math.max(2, Math.round((bar.count / maxCount) * 80)) }}
            />
          </Flex>
        ))}
      </Flex>
      <Flex gap={2} mt={4}>
        {bars.map((bar, i) => (
          <Text key={i} fz="0.6rem" c="dimmed" ta="center" truncate style={{ flex: 1, minWidth: 0 }}>
            {[bar.month, bar.year].filter(Boolean).join(' ') || ' '}
          </Text>
        ))}
      </Flex>
    </SectionCard>
  );
}
