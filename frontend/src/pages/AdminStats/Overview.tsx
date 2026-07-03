import { Badge, Box, Code, Flex, Grid, Text } from '@radix-ui/themes';
import { IconChartBar, IconGitBranch } from '@tabler/icons-react';
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
    <Grid columns={{ initial: '1', sm: '3' }} gap="3">
      <SectionCard title="CSIP-AUS Versions" icon={<IconGitBranch size={16} />}>
        <Flex direction="column" gap="1">
          {versions.map(([version, count]) => (
            <Flex key={version} justify="between" align="center">
              <Code>{version}</Code>
              <Badge color="green">
                {count} run group{count !== 1 ? 's' : ''}
              </Badge>
            </Flex>
          ))}
        </Flex>
      </SectionCard>

      <Box style={{ gridColumn: 'span 2' }}>
        <SectionCard
          title="Current Compliance (latest run per procedure per group)"
          icon={<IconChartBar size={16} />}
        >
          <Grid columns="2" mb="3">
            <Flex direction="column" align="center">
              <Text size="8" weight="bold" color="green">
                {totalPassed}
              </Text>
              <Text size="2" color="gray">
                Currently Passing
              </Text>
            </Flex>
            <Flex direction="column" align="center">
              <Text size="8" weight="bold" color="red">
                {totalFailed}
              </Text>
              <Text size="2" color="gray">
                Currently Failing
              </Text>
            </Flex>
          </Grid>
          {passRate !== null && (
            <>
              <Flex justify="between" mb="1">
                <Text size="2">Pass rate</Text>
                <Text size="2" weight="bold">
                  {passRate}%
                </Text>
              </Flex>
              <Flex style={{ height: 24, borderRadius: 'var(--radius-2)', overflow: 'hidden' }}>
                <Flex
                  align="center"
                  justify="center"
                  style={{
                    width: `${passRate}%`,
                    backgroundColor: 'var(--green-9)',
                    color: 'white',
                    fontSize: '0.75rem',
                  }}
                >
                  {totalPassed} passing
                </Flex>
                <Flex
                  align="center"
                  justify="center"
                  style={{
                    width: `${100 - passRate}%`,
                    backgroundColor: 'var(--red-9)',
                    color: 'white',
                    fontSize: '0.75rem',
                  }}
                >
                  {totalFailed} failing
                </Flex>
              </Flex>
            </>
          )}
        </SectionCard>
      </Box>
    </Grid>
  );
}
