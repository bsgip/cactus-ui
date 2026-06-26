import { Box, Button, Callout, Code, Flex, IconButton, Separator, Text } from '@radix-ui/themes';
import { IconArrowLeft, IconGripVertical, IconX } from '@tabler/icons-react';
import { Fragment, useState } from 'react';
import type { PlaylistTest } from '../../api/types';

interface PlaylistQueueProps {
  queue: PlaylistTest[];
  isStarting: boolean;
  onReorder: (from: number, to: number) => void;
  onRemove: (index: number) => void;
  onStart: () => void;
}

export function PlaylistQueue({
  queue,
  isStarting,
  onReorder,
  onRemove,
  onStart,
}: PlaylistQueueProps) {
  const [dragIndex, setDragIndex] = useState<number | null>(null);
  const [overIndex, setOverIndex] = useState<number | null>(null);

  const endDrag = () => {
    setDragIndex(null);
    setOverIndex(null);
  };
  const handleDrop = () => {
    if (dragIndex !== null && overIndex !== null && dragIndex !== overIndex) {
      onReorder(dragIndex, overIndex);
    }
    endDrag();
  };

  return (
    <>
      <Flex gap="2" align="center" py="1">
        <Text weight="medium" style={{ flex: 1 }}>
          Current Playlist
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
        <Callout.Root color="blue">
          <Callout.Icon>
            <IconArrowLeft size={16} />
          </Callout.Icon>
          <Callout.Text>
            Pick tests from the <strong>Test Library</strong> to build your playlist, then drag to
            set the order and press Start.
          </Callout.Text>
        </Callout.Root>
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
              <Flex
                gap="2"
                align="center"
                draggable
                onDragStart={() => setDragIndex(i)}
                onDragOver={(e) => {
                  e.preventDefault();
                  setOverIndex(i);
                }}
                onDrop={handleDrop}
                onDragEnd={endDrag}
                style={{
                  padding: '5px 10px',
                  cursor: 'grab',
                  opacity: dragIndex === i ? 0.4 : 1,
                  background:
                    dragIndex !== null && overIndex === i && dragIndex !== i
                      ? 'var(--gray-3)'
                      : undefined,
                }}
              >
                <IconGripVertical size={14} color="var(--gray-8)" aria-hidden />
                <Text size="1" color="gray" style={{ width: '1.5em', textAlign: 'right' }}>
                  {i + 1}
                </Text>
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

      <Text as="div" size="1" color="gray" mt="1">
        Test startup may take up to 30s.
      </Text>
    </>
  );
}
