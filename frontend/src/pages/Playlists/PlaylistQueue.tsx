import { ActionIcon, Alert, Button, Code, Divider, Group, Paper, Stack, Text } from '@mantine/core';
import { IconChevronDown, IconChevronUp, IconX } from '@tabler/icons-react';
import { Fragment } from 'react';
import type { PlaylistTest } from '../../api/types';

interface PlaylistQueueProps {
  queue: PlaylistTest[];
  isStarting: boolean;
  onMoveUp: (index: number) => void;
  onMoveDown: (index: number) => void;
  onRemove: (index: number) => void;
  onStart: () => void;
}

export function PlaylistQueue({
  queue,
  isStarting,
  onMoveUp,
  onMoveDown,
  onRemove,
  onStart,
}: PlaylistQueueProps) {
  return (
    <>
      <Group gap="sm" wrap="nowrap" py={5}>
        <Text fw={500} flex={1}>
          Current Playlist
        </Text>
        <Text size="sm" c="dimmed">
          May take up to 30s per test
        </Text>
        <Button
          size="xs"
          color="cyan"
          disabled={queue.length === 0}
          loading={isStarting}
          onClick={onStart}
        >
          Start Playlist
        </Button>
      </Group>

      {queue.length === 0 ? (
        <Alert color="yellow" py="xs">
          <strong>No tests selected.</strong> Click tests in the library to build your playlist.
        </Alert>
      ) : (
        <Paper withBorder radius="sm">
          <Stack gap={0}>
            {queue.map((t, i) => (
              <Fragment key={t.id}>
                {i > 0 && <Divider />}
                <Group gap="sm" wrap="nowrap" p="5px 10px">
                  <Stack gap={1}>
                    <ActionIcon
                      variant="default"
                      size="xs"
                      disabled={i === 0}
                      aria-label={`Move ${t.id} up`}
                      onClick={() => onMoveUp(i)}
                    >
                      <IconChevronUp size={12} />
                    </ActionIcon>
                    <ActionIcon
                      variant="default"
                      size="xs"
                      disabled={i === queue.length - 1}
                      aria-label={`Move ${t.id} down`}
                      onClick={() => onMoveDown(i)}
                    >
                      <IconChevronDown size={12} />
                    </ActionIcon>
                  </Stack>
                  <Text component="span" flex={1} miw={0}>
                    <Code>{t.id}</Code>
                    <Text component="small" size="xs" c="dimmed" ml={6}>
                      {t.description}
                    </Text>
                  </Text>
                  <ActionIcon
                    variant="outline"
                    color="red"
                    size="sm"
                    aria-label={`Remove ${t.id}`}
                    onClick={() => onRemove(i)}
                  >
                    <IconX size={14} />
                  </ActionIcon>
                </Group>
              </Fragment>
            ))}
          </Stack>
        </Paper>
      )}
    </>
  );
}
