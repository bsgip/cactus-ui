import { Button, Group, Progress, Stack, Text } from '@mantine/core';
import { useState } from 'react';
import type { UserLeaderboardEntry } from '../../api/types';
import { SectionCard } from '../../components/SectionCard';

function LeaderboardRow({
  entry,
  rank,
  maxRunCount,
}: {
  entry: UserLeaderboardEntry;
  rank: number;
  maxRunCount: number;
}) {
  const pct = maxRunCount > 0 ? Math.round((entry.run_count / maxRunCount) * 1000) / 10 : 0;
  return (
    <Group gap="xs" wrap="nowrap">
      <Text c="dimmed" size="sm" w={24} ta="right">
        {rank}
      </Text>
      <Text size="sm" w={180} truncate>
        {entry.name}
      </Text>
      <Progress value={pct} color="green" size={16} style={{ flex: 1 }} />
      <Text fw={700} size="sm" w={36} ta="right">
        {entry.run_count}
      </Text>
    </Group>
  );
}

export function UserLeaderboard({ entries }: { entries: UserLeaderboardEntry[] }) {
  const [showAll, setShowAll] = useState(false);
  const maxRunCount = entries.length > 0 ? entries[0].run_count : 1;
  const displayed = showAll ? entries : entries.slice(0, 20);

  return (
    <SectionCard title="Runs Per User">
      {entries.length === 0 ? (
        <Text c="dimmed" size="sm">
          No data yet.
        </Text>
      ) : (
        <Stack gap="xs">
          {displayed.map((entry, i) => (
            <LeaderboardRow key={entry.name} entry={entry} rank={i + 1} maxRunCount={maxRunCount} />
          ))}
          {!showAll && entries.length > 20 && (
            <Button variant="default" size="xs" mt="xs" onClick={() => setShowAll(true)}>
              Show all {entries.length} users
            </Button>
          )}
        </Stack>
      )}
    </SectionCard>
  );
}
