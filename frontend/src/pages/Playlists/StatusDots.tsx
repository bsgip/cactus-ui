import { Box, Flex, Tooltip } from '@radix-ui/themes';
import type { PlaylistTestStatus } from '../../api/types';
import { RESULT_COLOR } from '../../utils/status';
import { statusDots } from './statusDots';

export function StatusDots({ testStatuses }: { testStatuses: PlaylistTestStatus[] }) {
  const { dots } = statusDots(testStatuses);
  return (
    <Flex gap="1" wrap="wrap">
      {dots.map((dot, i) => (
        <Tooltip key={i} content={dot.title}>
          <Box
            style={{
              width: 14,
              height: 14,
              borderRadius: '50%',
              backgroundColor: RESULT_COLOR[dot.kind],
            }}
          />
        </Tooltip>
      ))}
    </Flex>
  );
}
