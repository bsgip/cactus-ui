import { Link, Text } from '@radix-ui/themes';
import { Link as RouterLink } from 'react-router-dom';
import { SectionCard } from '../../components/SectionCard';

export function DeviceCapabilityCard() {
  return (
    <SectionCard title="DeviceCapability URI">
      <Text as="p" mb="1">
        Each run group has a single DeviceCapability URI that is shared across all of its test runs,
        shown alongside the run group above.
      </Text>
      <Text as="p" size="2" color="gray">
        <strong>Note:</strong> only <em>one</em> test run can be active at any given time, and a test
        must be started from the{' '}
        <Link asChild>
          <RouterLink to="/runs">Runs</RouterLink>
        </Link>{' '}
        page before the URI becomes active.
      </Text>
    </SectionCard>
  );
}
