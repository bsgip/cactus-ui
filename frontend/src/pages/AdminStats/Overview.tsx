import { Badge, Grid, Group, Progress, SimpleGrid, Stack, Text } from '@mantine/core';
import { SectionCard } from '../../components/SectionCard';

interface OverviewProps {
  versionCounts: { [k: string]: number };
  totalPassed: number;
  totalFailed: number;
}

export function Overview({ versionCounts, totalPassed, totalFailed }: OverviewProps) {
  const versions = Object.entries(versionCounts).sort(([a], [b]) => a.localeCompare(b));
  const assessed = totalPassed + totalFailed;
  const passRate = assessed > 0 ? Math.round((totalPassed / assessed) * 1000) / 10 : null;

  return (
    <Grid>
      <Grid.Col span={{ base: 12, sm: 4 }}>
        <SectionCard title="CSIP-AUS Versions">
          <Stack gap="xs">
            {versions.map(([version, count]) => (
              <Group key={version} justify="space-between">
                <Text component="code" size="sm">
                  {version}
                </Text>
                <Badge color="green">
                  {count} run group{count !== 1 ? 's' : ''}
                </Badge>
              </Group>
            ))}
          </Stack>
        </SectionCard>
      </Grid.Col>

      <Grid.Col span={{ base: 12, sm: 8 }}>
        <SectionCard title="Current Compliance (latest run per procedure per group)">
          <SimpleGrid cols={2} mb="md">
            <Stack gap={0} align="center">
              <Text fz="xl" fw={700} c="green">
                {totalPassed}
              </Text>
              <Text size="sm" c="dimmed">
                Currently Passing
              </Text>
            </Stack>
            <Stack gap={0} align="center">
              <Text fz="xl" fw={700} c="red">
                {totalFailed}
              </Text>
              <Text size="sm" c="dimmed">
                Currently Failing
              </Text>
            </Stack>
          </SimpleGrid>
          {passRate !== null && (
            <>
              <Group justify="space-between" mb={4}>
                <Text size="sm">Pass rate</Text>
                <Text size="sm" fw={700}>
                  {passRate}%
                </Text>
              </Group>
              <Progress.Root size={24}>
                <Progress.Section value={passRate} color="green">
                  <Progress.Label>{totalPassed} passing</Progress.Label>
                </Progress.Section>
                <Progress.Section value={100 - passRate} color="red">
                  <Progress.Label>{totalFailed} failing</Progress.Label>
                </Progress.Section>
              </Progress.Root>
            </>
          )}
        </SectionCard>
      </Grid.Col>
    </Grid>
  );
}
