import { Box, Group, Tooltip } from '@mantine/core';
import type { PlaylistTestStatus } from '../../api/types';
import { DOT_COLOR, statusDots } from './statusDots';

export function StatusDots({ testStatuses }: { testStatuses: PlaylistTestStatus[] }) {
  const { dots } = statusDots(testStatuses);
  return (
    <Group gap={4} wrap="wrap">
      {dots.map((dot, i) => (
        <Tooltip key={i} label={dot.title} withArrow>
          <Box
            w={14}
            h={14}
            style={{ borderRadius: '50%', backgroundColor: DOT_COLOR[dot.kind] }}
          />
        </Tooltip>
      ))}
    </Group>
  );
}
