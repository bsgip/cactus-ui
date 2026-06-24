import { Text } from '@mantine/core';
import { Link } from 'react-router-dom';
import { SectionCard } from '../../components/SectionCard';

export function DeviceCapabilityCard() {
  return (
    <SectionCard title="DeviceCapability URI">
      <Text mb="xs">
        Each run group has a single DeviceCapability URI that is shared across all of its test runs,
        shown alongside the run group above.
      </Text>
      <Text size="sm" c="dimmed">
        <strong>Note:</strong> only <em>one</em> test run can be active at any given time, and a test
        must be started from the{' '}
        <Text component={Link} to="/runs" c="blue" inherit>
          Runs
        </Text>{' '}
        page before the URI becomes active.
      </Text>
    </SectionCard>
  );
}
