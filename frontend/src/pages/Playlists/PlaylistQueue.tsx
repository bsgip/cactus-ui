import { Box, Button, Code, Flex, IconButton, Separator, Text } from '@radix-ui/themes';
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
      <Flex gap="2" align="center" py="1">
        <Text weight="medium" style={{ flex: 1 }}>
          Current Playlist
        </Text>
        <Text size="2" color="gray">
          May take up to 30s per test
        </Text>
        <Button
          size="1"
          color="cyan"
          disabled={queue.length === 0}
          loading={isStarting}
          onClick={onStart}
        >
          Start Playlist
        </Button>
      </Flex>

      {queue.length === 0 ? (
        <Box
          role="alert"
          style={{
            backgroundColor: 'var(--yellow-3)',
            border: '1px solid var(--yellow-6)',
            borderRadius: 'var(--radius-3)',
            padding: 'var(--space-2)',
          }}
        >
          <strong>No tests selected.</strong> Click tests in the library to build your playlist.
        </Box>
      ) : (
        <Box
          style={{
            border: '1px solid var(--gray-5)',
            borderRadius: 'var(--radius-2)',
            overflow: 'hidden',
          }}
        >
          {queue.map((t, i) => (
            <Fragment key={t.id}>
              {i > 0 && <Separator size="4" />}
              <Flex gap="2" align="center" style={{ padding: '5px 10px' }}>
                <Flex direction="column" gap="1">
                  <IconButton
                    variant="soft"
                    color="gray"
                    size="1"
                    disabled={i === 0}
                    aria-label={`Move ${t.id} up`}
                    onClick={() => onMoveUp(i)}
                  >
                    <IconChevronUp size={12} />
                  </IconButton>
                  <IconButton
                    variant="soft"
                    color="gray"
                    size="1"
                    disabled={i === queue.length - 1}
                    aria-label={`Move ${t.id} down`}
                    onClick={() => onMoveDown(i)}
                  >
                    <IconChevronDown size={12} />
                  </IconButton>
                </Flex>
                <Text as="span" style={{ flex: 1, minWidth: 0 }}>
                  <Code>{t.id}</Code>
                  <Text size="1" color="gray" ml="2">
                    {t.description}
                  </Text>
                </Text>
                <IconButton
                  variant="outline"
                  color="red"
                  size="1"
                  aria-label={`Remove ${t.id}`}
                  onClick={() => onRemove(i)}
                >
                  <IconX size={14} />
                </IconButton>
              </Flex>
            </Fragment>
          ))}
        </Box>
      )}
    </>
  );
}
