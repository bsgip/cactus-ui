import { Box, Code, Flex, IconButton, Separator, Text } from '@radix-ui/themes';
import { IconGripVertical, IconX } from '@tabler/icons-react';
import { Fragment, useState } from 'react';

interface DraggableTestListProps {
  // Keyed by index, not id: the same test can legitimately appear twice (e.g. a retried test).
  items: { id: string; description?: string }[];
  onReorder: (from: number, to: number) => void;
  onRemove: (index: number) => void;
}

// Numbered drag-to-reorder list of test procedures with per-row remove buttons. Used both when
// building a playlist (PlaylistQueue) and when editing a running one (PlaylistEditDialog).
export function DraggableTestList({ items, onReorder, onRemove }: DraggableTestListProps) {
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
    <Box
      style={{
        border: '1px solid var(--gray-5)',
        borderRadius: 'var(--radius-2)',
        overflow: 'hidden',
      }}
    >
      {items.map((item, i) => (
        <Fragment key={i}>
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
              <Code>{item.id}</Code>
              {item.description && (
                <Text size="1" color="gray" ml="2">
                  {item.description}
                </Text>
              )}
            </Text>
            <IconButton
              variant="outline"
              color="red"
              size="1"
              aria-label={`Remove ${item.id}`}
              onClick={() => onRemove(i)}
            >
              <IconX size={14} />
            </IconButton>
          </Flex>
        </Fragment>
      ))}
    </Box>
  );
}
