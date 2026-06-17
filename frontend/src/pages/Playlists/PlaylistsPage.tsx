import { Button, Divider, Grid, Group, Menu, Title } from '@mantine/core';
import { useDocumentTitle } from '@mantine/hooks';
import { IconChevronDown } from '@tabler/icons-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  fetchPlaylistSessions,
  fetchPlaylistTests,
  finalisePlaylist,
  initPlaylist,
} from '../../api/playlists';
import { fetchRunGroups } from '../../api/runs';
import type { PlaylistTest } from '../../api/types';
import { Banner } from '../../components/Banner';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageSpinner } from '../../components/PageSpinner';
import { useSession } from '../../hooks/useSession';
import { PlaylistQueue } from './PlaylistQueue';
import { PlaylistSessions } from './PlaylistSessions';
import { TestLibrary } from './TestLibrary';

const POLL_INTERVAL_MS = 10_000;

// Port of playlists.html / group_playlists_page. Builds a playlist from the test library
// and starts it; shows active + past playlist sessions for the run group.
export function PlaylistsPage() {
  useDocumentTitle('Playlists - CACTUS');
  const { runGroupId: runGroupIdParam } = useParams();
  const runGroupId = Number(runGroupIdParam);
  const queryClient = useQueryClient();
  const { data: session } = useSession();

  const [queue, setQueue] = useState<PlaylistTest[]>([]);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    setQueue([]);
    setActionError(null);
  }, [runGroupId]);

  const groupsQuery = useQuery({
    queryKey: ['run_groups', 'mine'],
    queryFn: () => fetchRunGroups(false),
  });

  const testsQuery = useQuery({
    queryKey: ['playlist_tests', runGroupId],
    queryFn: () => fetchPlaylistTests(runGroupId),
  });

  const sessionsQuery = useQuery({
    queryKey: ['playlist_sessions', runGroupId],
    queryFn: () => fetchPlaylistSessions(runGroupId),
    // Poll while a playlist is active; stop once everything is finalised.
    refetchInterval: (query) =>
      query.state.data?.some((s) => s.is_active) ? POLL_INTERVAL_MS : false,
  });

  const onActionError = (error: Error) => setActionError(error.message);

  const initMutation = useMutation({
    mutationFn: (procedures: string[]) => initPlaylist(runGroupId, procedures),
    onSuccess: ({ run_id }) => window.location.assign(`/run/${run_id}`),
    onError: onActionError,
  });

  const finaliseMutation = useMutation({
    mutationFn: finalisePlaylist,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['playlist_sessions', runGroupId] });
    },
    onError: onActionError,
  });

  const toggleTest = (test: PlaylistTest) =>
    setQueue((q) =>
      q.some((t) => t.id === test.id) ? q.filter((t) => t.id !== test.id) : [...q, test]
    );
  const moveUp = (i: number) =>
    setQueue((q) => (i <= 0 ? q : swap(q, i - 1, i)));
  const moveDown = (i: number) =>
    setQueue((q) => (i >= q.length - 1 ? q : swap(q, i, i + 1)));
  const removeAt = (i: number) => setQueue((q) => q.filter((_, idx) => idx !== i));

  const runGroups = groupsQuery.data?.items ?? [];
  const activeRunGroup = runGroups.find((rg) => rg.run_group_id === runGroupId);

  if (testsQuery.isPending || groupsQuery.isPending) {
    return <PageSpinner />;
  }

  return (
    <>
      <Banner message={session?.banner_message} />
      {groupsQuery.error && <ErrorAlert message="Unable to fetch run groups." />}
      {testsQuery.error && <ErrorAlert message="Unable to fetch test procedures." />}
      {actionError && <ErrorAlert message={actionError} />}

      <Group gap="sm" mb="xs">
        {runGroups.length < 2 ? (
          activeRunGroup && <Title order={2}>Playlists for {activeRunGroup.name}</Title>
        ) : (
          <>
            <Title order={2}>Playlists for</Title>
            <Menu>
              <Menu.Target>
                <Button rightSection={<IconChevronDown size={16} />}>{activeRunGroup?.name}</Button>
              </Menu.Target>
              <Menu.Dropdown>
                {runGroups
                  .filter((rg) => rg.run_group_id !== runGroupId)
                  .map((rg) => (
                    <Menu.Item
                      key={rg.run_group_id}
                      component={Link}
                      to={`/group/${rg.run_group_id}/playlists`}
                    >
                      {rg.name}
                    </Menu.Item>
                  ))}
              </Menu.Dropdown>
            </Menu>
          </>
        )}
      </Group>

      <Divider mb="md" />

      {testsQuery.data && (
        <Grid>
          <Grid.Col span={{ base: 12, md: 4 }}>
            <TestLibrary
              testsByCategory={testsQuery.data.tests_by_category}
              classes={testsQuery.data.classes}
              queuedIds={new Set(queue.map((t) => t.id))}
              onToggle={toggleTest}
            />
          </Grid.Col>
          <Grid.Col span={{ base: 12, md: 8 }}>
            <PlaylistQueue
              queue={queue}
              isStarting={initMutation.isPending}
              onMoveUp={moveUp}
              onMoveDown={moveDown}
              onRemove={removeAt}
              onStart={() => initMutation.mutate(queue.map((t) => t.id))}
            />
            <Divider my="sm" />
            {sessionsQuery.error ? (
              <ErrorAlert message="Failed to load session history." />
            ) : (
              <PlaylistSessions
                sessions={sessionsQuery.data ?? []}
                isFinalising={finaliseMutation.isPending}
                onFinalise={(runId) => finaliseMutation.mutate(runId)}
              />
            )}
          </Grid.Col>
        </Grid>
      )}
    </>
  );
}

function swap<T>(arr: T[], i: number, j: number): T[] {
  const next = arr.slice();
  [next[i], next[j]] = [next[j], next[i]];
  return next;
}
