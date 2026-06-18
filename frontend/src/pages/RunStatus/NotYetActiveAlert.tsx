import { Alert, Button, Text } from '@mantine/core';
import { IconAlertTriangle, IconPlayerPlay } from '@tabler/icons-react';
import { Link } from 'react-router-dom';
import type { CurrentActiveRun } from '../../api/types';

interface Props {
  currentActiveRun: CurrentActiveRun;
  total: number;
  isAdminView: boolean;
}

// Shown when an initialised run is queued behind the currently-active playlist run. Points the
// user at the run that is actually live (run_status.html, the "This Test is Not Yet Active" alert).
export function NotYetActiveAlert({ currentActiveRun, total, isAdminView }: Props) {
  return (
    <Alert
      color="yellow"
      role="alert"
      icon={<IconAlertTriangle size={18} />}
      title="This Test is Not Yet Active"
    >
      <Text mb="sm">
        This test is part of a playlist but has not started yet. The currently active test is{' '}
        <strong>{currentActiveRun.test_procedure_id}</strong> (Test {currentActiveRun.order + 1} of{' '}
        {total}).
      </Text>
      <Button
        color="yellow"
        component={Link}
        to={`${isAdminView ? '/admin' : ''}/run/${currentActiveRun.run_id}`}
        leftSection={<IconPlayerPlay size={16} />}
      >
        Go to Active Test
      </Button>
    </Alert>
  );
}
