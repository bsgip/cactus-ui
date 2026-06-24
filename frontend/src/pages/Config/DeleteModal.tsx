import { Button, Code, Group, Stack, Text } from '@mantine/core';
import { IconTrash } from '@tabler/icons-react';
import type { RunGroupResponse } from '../../api/types';
import { ModalButton } from '../../components/ModalButton';

export function DeleteModal({
  runGroup,
  onDelete,
  isDeleting,
}: {
  runGroup: RunGroupResponse;
  onDelete: () => void;
  isDeleting: boolean;
}) {
  return (
    <ModalButton
      title="Confirm Delete"
      trigger={(open) => (
        <Button variant="outline" color="red" leftSection={<IconTrash size={14} />} onClick={open}>
          Delete
        </Button>
      )}
    >
      {(close) => (
        <Stack>
          <Text>
            You are about to permanently delete <strong>{runGroup.name}</strong>{' '}
            <Code>{runGroup.csip_aus_version}</Code>. Once deleted, this group and the associated{' '}
            {runGroup.total_runs} run(s) will be gone forever.
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>
              Cancel
            </Button>
            <Button
              color="red"
              leftSection={<IconTrash size={14} />}
              loading={isDeleting}
              onClick={() => {
                onDelete();
                close();
              }}
            >
              Delete {runGroup.name}
            </Button>
          </Group>
        </Stack>
      )}
    </ModalButton>
  );
}
