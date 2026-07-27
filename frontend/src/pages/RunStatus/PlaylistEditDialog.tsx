import { Button, Callout, Dialog, Flex, Spinner, Text } from '@radix-ui/themes';
import { IconAlertTriangle, IconPencil } from '@tabler/icons-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { ApiError } from '../../api/client';
import { fetchPlaylistTests, updatePlaylist } from '../../api/playlists';
import { DraggableTestList } from '../Playlists/DraggableTestList';
import { TestLibrary } from '../Playlists/TestLibrary';
import type { PlaylistRunRow } from './runStatusModel';

interface Props {
  runId: number;
  upcomingRuns: PlaylistRunRow[]; // status === 'initialised', in playlist order
  activeRunId: number;
  runGroupId: number | null;
  onUpdated: () => void; // called after a successful save, or on 409 to refetch the stale playlist
}

// Edits the upcoming (not-yet-run) tail of a playlist: reorder, remove, and add tests from the
// same catalog used to build playlists. The active and completed entries are never touched -
// the orchestrator deletes and recreates only the upcoming rows, so their run_ids change on save.
export function PlaylistEditDialog({
  runId,
  upcomingRuns,
  activeRunId,
  runGroupId,
  onUpdated,
}: Props) {
  const [open, setOpen] = useState(false);
  const [tail, setTail] = useState<string[]>([]);
  const [conflict, setConflict] = useState(false);

  const testsQuery = useQuery({
    queryKey: ['playlist_tests', runGroupId],
    queryFn: () => fetchPlaylistTests(runGroupId as number),
    enabled: open && runGroupId != null,
  });

  const mutation = useMutation({
    mutationFn: () => updatePlaylist(runId, tail, activeRunId),
    onMutate: () => setConflict(false),
    onSuccess: () => {
      setOpen(false);
      onUpdated();
    },
    onError: (error: Error) => {
      if (error instanceof ApiError && error.status === 409) {
        setConflict(true);
        onUpdated(); // refetch so the caller has the current playlist once the user retries
      }
    },
  });

  const toggleTest = (testProcedureId: string) =>
    setTail((t) =>
      t.includes(testProcedureId)
        ? t.filter((id) => id !== testProcedureId)
        : [...t, testProcedureId]
    );

  const openDialog = () => {
    setTail(upcomingRuns.map((r) => r.test_procedure_id));
    setConflict(false);
    setOpen(true);
  };

  const removeAt = (i: number) => setTail((t) => t.filter((_, idx) => idx !== i));
  const reorder = (from: number, to: number) =>
    setTail((t) => {
      const next = t.slice();
      const [moved] = next.splice(from, 1);
      next.splice(to, 0, moved);
      return next;
    });

  return (
    <>
      <Button size="1" variant="soft" onClick={openDialog}>
        <IconPencil size={14} />
        Edit Playlist
      </Button>
      <Dialog.Root open={open} onOpenChange={(o) => !o && setOpen(false)}>
        <Dialog.Content maxWidth="700px">
          <Dialog.Title>Edit upcoming tests</Dialog.Title>
          <Dialog.Description size="2" mb="3">
            Change which tests run after the current one finishes &mdash; click a test in the
            library to add or remove it. Tests that have already run, and the test running now, are
            not affected.
          </Dialog.Description>

          {conflict && (
            <Callout.Root color="red" mb="3">
              <Callout.Icon>
                <IconAlertTriangle size={16} />
              </Callout.Icon>
              <Callout.Text>
                The playlist advanced while you were editing. The view has been refreshed - please
                try again.
              </Callout.Text>
            </Callout.Root>
          )}
          {mutation.isError && !conflict && (
            <Callout.Root color="red" mb="3">
              <Callout.Icon>
                <IconAlertTriangle size={16} />
              </Callout.Icon>
              <Callout.Text>Failed to save the playlist. Please try again.</Callout.Text>
            </Callout.Root>
          )}

          <Flex align="baseline" gap="2" mb="1">
            <Text weight="medium">Up next</Text>
            {tail.length > 0 && (
              <Text size="1" color="gray">
                runs top to bottom &mdash; drag to reorder
              </Text>
            )}
          </Flex>
          {tail.length === 0 ? (
            <Callout.Root color="gray" mb="3">
              <Callout.Text>
                No tests queued &mdash; the playlist will finish after the current test. Add tests
                from the library below to keep it going.
              </Callout.Text>
            </Callout.Root>
          ) : (
            <Flex direction="column" mb="3">
              <DraggableTestList
                items={tail.map((id) => ({ id }))}
                onReorder={reorder}
                onRemove={removeAt}
              />
            </Flex>
          )}

          {testsQuery.isLoading && (
            <Flex align="center" gap="2" mb="3">
              <Spinner size="1" />
              <Text size="2" color="gray">
                Loading test library&hellip;
              </Text>
            </Flex>
          )}
          {testsQuery.isError && (
            <Callout.Root color="red" mb="3">
              <Callout.Text>Failed to load the test library.</Callout.Text>
            </Callout.Root>
          )}
          {testsQuery.data && (
            <TestLibrary
              testsByCategory={testsQuery.data.tests_by_category}
              classes={testsQuery.data.classes}
              queuedIds={new Set(tail)}
              onToggle={(test) => toggleTest(test.id)}
            />
          )}

          <Flex gap="3" mt="4" justify="end">
            <Dialog.Close>
              <Button variant="soft" color="gray">
                Cancel
              </Button>
            </Dialog.Close>
            <Button loading={mutation.isPending} onClick={() => mutation.mutate()}>
              Save changes
            </Button>
          </Flex>
        </Dialog.Content>
      </Dialog.Root>
    </>
  );
}
