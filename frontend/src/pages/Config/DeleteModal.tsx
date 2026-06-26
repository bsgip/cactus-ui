import { Button, Code, Flex, Text } from '@radix-ui/themes';
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
        <Button variant="outline" color="red" onClick={open}>
          <IconTrash size={14} />
          Delete
        </Button>
      )}
    >
      {(close) => (
        <Flex direction="column" gap="3">
          <Text>
            You are about to permanently delete <strong>{runGroup.name}</strong>{' '}
            <Code>{runGroup.csip_aus_version}</Code>. Once deleted, this group and the associated{' '}
            {runGroup.total_runs} run(s) will be gone forever.
          </Text>
          <Flex justify="end" gap="2">
            <Button variant="soft" color="gray" onClick={close}>
              Cancel
            </Button>
            <Button
              color="red"
              loading={isDeleting}
              onClick={() => {
                onDelete();
                close();
              }}
            >
              <IconTrash size={14} />
              Delete {runGroup.name}
            </Button>
          </Flex>
        </Flex>
      )}
    </ModalButton>
  );
}
