import { Button, Callout, Flex, Text } from '@radix-ui/themes';
import { IconArrowLeft } from '@tabler/icons-react';
import type { PlaylistTest } from '../../api/types';
import { DraggableTestList } from './DraggableTestList';

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
        <DraggableTestList items={queue} onReorder={onReorder} onRemove={onRemove} />
      )}

      <Text as="div" size="1" color="gray" mt="1">
        Test startup may take up to 30s.
      </Text>
    </>
  );
}
