import { Box, Button, DropdownMenu, Flex, Grid, Heading, Separator } from '@radix-ui/themes';
import { IconChevronDown } from '@tabler/icons-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
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
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { useSession } from '../../hooks/useSession';
import { PlaylistQueue } from './PlaylistQueue';
import { PlaylistsIntro } from './PlaylistsIntro';
import { ActivePlaylists, PastSessions } from './PlaylistSessions';
import { TestLibrary } from './TestLibrary';

const POLL_INTERVAL_MS = 10_000;

// Builds a playlist from the test library and starts it; shows active + past playlist
// sessions for the run group.
export function PlaylistsPage() {
  useDocumentTitle('Playlists - CACTUS');
  const { runGroupId: runGroupIdParam } = useParams();
  const runGroupId = Number(runGroupIdParam);
  const navigate = useNavigate();
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
    onSuccess: ({ run_id }) => void navigate(`/run/${run_id}`),
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
  const reorder = (from: number, to: number) =>
    setQueue((q) => {
      const next = q.slice();
      const [moved] = next.splice(from, 1);
      next.splice(to, 0, moved);
      return next;
    });
  const removeAt = (i: number) => setQueue((q) => q.filter((_, idx) => idx !== i));

  const runGroups = groupsQuery.data?.items ?? [];
  const activeRunGroup = runGroups.find((rg) => rg.run_group_id === runGroupId);

  const sessions = sessionsQuery.data ?? [];
  const activeSessions = sessions.filter((s) => s.is_active);
  const pastSessions = sessions.filter((s) => !s.is_active);

  if (testsQuery.isPending || groupsQuery.isPending) {
    return <PageSpinner />;
  }

  return (
    <>
      <Banner message={session?.banner_message} />
      {groupsQuery.error && <ErrorAlert message="Unable to fetch run groups." />}
      {testsQuery.error && <ErrorAlert message="Unable to fetch test procedures." />}
      {actionError && <ErrorAlert message={actionError} />}

      <Flex gap="2" align="center" mb="1">
        {runGroups.length < 2 ? (
          activeRunGroup && (
            <Heading as="h2" size="6">
              Playlists for {activeRunGroup.name}
            </Heading>
          )
        ) : (
          <>
            <Heading as="h2" size="6">
              Playlists for
            </Heading>
            <DropdownMenu.Root>
              <DropdownMenu.Trigger>
                <Button color="blue">
                  {activeRunGroup?.name}
                  <IconChevronDown size={16} />
                </Button>
              </DropdownMenu.Trigger>
              <DropdownMenu.Content>
                {runGroups
                  .filter((rg) => rg.run_group_id !== runGroupId)
                  .map((rg) => (
                    <DropdownMenu.Item
                      key={rg.run_group_id}
                      onSelect={() => navigate(`/group/${rg.run_group_id}/playlists`)}
                    >
                      {rg.name}
                    </DropdownMenu.Item>
                  ))}
              </DropdownMenu.Content>
            </DropdownMenu.Root>
          </>
        )}
      </Flex>

      <Separator size="4" mb="3" />

      <PlaylistsIntro />

      {activeSessions.length > 0 && (
        <Box mb="4">
          <ActivePlaylists
            sessions={activeSessions}
            isFinalising={finaliseMutation.isPending}
            onFinalise={(runId) => finaliseMutation.mutate(runId)}
          />
        </Box>
      )}

      {testsQuery.data && (
        <Grid columns={{ initial: '1', md: '3' }} gap="3">
          <TestLibrary
            testsByCategory={testsQuery.data.tests_by_category}
            classes={testsQuery.data.classes}
            queuedIds={new Set(queue.map((t) => t.id))}
            onToggle={toggleTest}
          />
          <Box style={{ gridColumn: 'span 2' }}>
            <PlaylistQueue
              queue={queue}
              isStarting={initMutation.isPending}
              onReorder={reorder}
              onRemove={removeAt}
              onStart={() => initMutation.mutate(queue.map((t) => t.id))}
            />
            <Separator size="4" my="2" />
            {sessionsQuery.error ? (
              <ErrorAlert message="Failed to load session history." />
            ) : (
              <PastSessions sessions={pastSessions} />
            )}
          </Box>
        </Grid>
      )}
    </>
  );
}
