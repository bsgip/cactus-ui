import { Box, Flex, Text } from '@radix-ui/themes';
import type { WeekBar } from '../../api/types';
import { SectionCard } from '../../components/SectionCard';

export function WeekBars({ bars }: { bars: WeekBar[] }) {
  if (bars.length === 0) return null;
  const maxCount = Math.max(...bars.map((b) => b.count), 1);

  return (
    <SectionCard title="Tests Per Week">
      <Flex align="end" gap="1" style={{ height: 110 }}>
        {bars.map((bar, i) => (
          <Flex key={i} direction="column" align="center" style={{ flex: 1, minWidth: 0 }}>
            <Text color="gray" style={{ fontSize: '0.6rem' }}>
              {bar.count}
            </Text>
            <Box
              title={`${bar.month || ''} ${bar.year || ''}: ${bar.count} runs`.trim()}
              style={{
                width: '100%',
                backgroundColor: 'var(--green-9)',
                height: Math.max(2, Math.round((bar.count / maxCount) * 80)),
              }}
            />
          </Flex>
        ))}
      </Flex>
      <Flex gap="1" mt="1">
        {bars.map((bar, i) => (
          <Text
            key={i}
            color="gray"
            align="center"
            truncate
            style={{ fontSize: '0.6rem', flex: 1, minWidth: 0 }}
          >
            {[bar.month, bar.year].filter(Boolean).join(' ') || ' '}
          </Text>
        ))}
      </Flex>
    </SectionCard>
  );
}
