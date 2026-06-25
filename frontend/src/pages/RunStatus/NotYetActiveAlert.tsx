import { Box, Button, Flex, Text } from '@radix-ui/themes';
import { IconAlertTriangle, IconPlayerPlay } from '@tabler/icons-react';
import { Link } from 'react-router-dom';
import type { CurrentActiveRun } from './runStatusModel';

interface Props {
  currentActiveRun: CurrentActiveRun;
  total: number;
  isAdminView: boolean;
}

// Shown when an initialised run is queued behind the currently-active playlist run. Points the
// user at the run that is actually live.
export function NotYetActiveAlert({ currentActiveRun, total, isAdminView }: Props) {
  return (
    <Box
      role="alert"
      style={{
        backgroundColor: 'var(--yellow-3)',
        border: '1px solid var(--yellow-6)',
        borderRadius: 'var(--radius-3)',
        padding: 'var(--space-3)',
      }}
    >
      <Flex gap="3" align="start">
        <IconAlertTriangle size={18} style={{ flexShrink: 0, marginTop: 2 }} />
        <Flex direction="column" gap="2" align="start">
          <Text weight="bold">This Test is Not Yet Active</Text>
          <Text>
            This test is part of a playlist but has not started yet. The currently active test is{' '}
            <strong>{currentActiveRun.test_procedure_id}</strong> (Test {currentActiveRun.order + 1}{' '}
            of {total}).
          </Text>
          <Button asChild color="yellow">
            <Link to={`${isAdminView ? '/admin' : ''}/run/${currentActiveRun.run_id}`}>
              <IconPlayerPlay size={16} />
              Go to Active Test
            </Link>
          </Button>
        </Flex>
      </Flex>
    </Box>
  );
}
