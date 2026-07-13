import { Button, Code, Flex, Text, TextField } from '@radix-ui/themes';
import { IconTrash } from '@tabler/icons-react';
import { useState } from 'react';
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
        <DeleteConfirmBody
          runGroup={runGroup}
          onDelete={onDelete}
          isDeleting={isDeleting}
          close={close}
        />
      )}
    </ModalButton>
  );
}

// Lives inside the dialog body so the typed confirmation resets on every close, however the
// dialog is dismissed (Cancel, Escape, overlay click) — it must never stay pre-armed.
function DeleteConfirmBody({
  runGroup,
  onDelete,
  isDeleting,
  close,
}: {
  runGroup: RunGroupResponse;
  onDelete: () => void;
  isDeleting: boolean;
  close: () => void;
}) {
  const [confirmText, setConfirmText] = useState('');
  const confirmed = confirmText === runGroup.name;

  return (
    <Flex direction="column" gap="3">
      <Text>
        You are about to permanently delete <strong>{runGroup.name}</strong>{' '}
        <Code>{runGroup.csip_aus_version}</Code>. Once deleted, this group and the associated{' '}
        {runGroup.total_runs} run(s) will be gone forever.
      </Text>
      <Text as="label" size="2">
        Type <strong>{runGroup.name}</strong> to confirm.
        <TextField.Root
          autoFocus
          mt="1"
          value={confirmText}
          onChange={(e) => setConfirmText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') close();
          }}
        />
      </Text>
      <Flex justify="end" gap="2">
        <Button variant="soft" color="gray" onClick={close}>
          Cancel
        </Button>
        <Button
          color="red"
          disabled={!confirmed}
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
  );
}
