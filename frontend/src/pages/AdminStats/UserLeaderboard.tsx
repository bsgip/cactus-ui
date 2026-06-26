import { Button, Flex, Progress, Text } from '@radix-ui/themes';
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
    <Flex gap="2" align="center">
      <Text color="gray" size="2" style={{ width: 24, textAlign: 'right' }}>
        {rank}
      </Text>
      <Text size="2" truncate style={{ width: 180 }}>
        {entry.name}
      </Text>
      <Progress value={pct} color="green" size="2" style={{ flex: 1 }} />
      <Text weight="bold" size="2" style={{ width: 36, textAlign: 'right' }}>
        {entry.run_count}
      </Text>
    </Flex>
  );
}

export function UserLeaderboard({ entries }: { entries: UserLeaderboardEntry[] }) {
  const [showAll, setShowAll] = useState(false);
  const maxRunCount = entries.length > 0 ? entries[0].run_count : 1;
  const displayed = showAll ? entries : entries.slice(0, 20);

  return (
    <SectionCard title="Runs Per User">
      {entries.length === 0 ? (
        <Text color="gray" size="2">
          No data yet.
        </Text>
      ) : (
        <Flex direction="column" gap="2">
          {displayed.map((entry, i) => (
            <LeaderboardRow key={entry.name} entry={entry} rank={i + 1} maxRunCount={maxRunCount} />
          ))}
          {!showAll && entries.length > 20 && (
            <Button variant="soft" color="gray" size="1" mt="1" onClick={() => setShowAll(true)}>
              Show all {entries.length} users
            </Button>
          )}
        </Flex>
      )}
    </SectionCard>
  );
}
