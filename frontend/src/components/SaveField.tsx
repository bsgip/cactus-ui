
import { Button, Flex, Text, TextField } from '@radix-ui/themes';
import { IconCheck, IconPencil } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type ComponentProps, type ReactNode } from 'react';
import { InfoPopover } from './InfoPopover';
import { useConfirm } from './useConfirm';

// A labelled input + save button with explicit state feedback: the button only enables once the
// value differs from what is saved, an "Unsaved changes" hint appears while dirty, and a green
// "Saved" indicator confirms a successful save. Overwriting an already-set value asks for
// confirmation first, since both identity values are baked into previously issued certificates.
export function SaveField({
  label,
  infoTitle,
  info,
  savedValue,
  placeholder,
  emptyHint,
  saveLabel,
  confirmTitle,
  confirmBody,
  inputProps,
  save,
  setError,
  mb = "6",
}: {
  label: string;
  infoTitle: string;
  info: ReactNode;
  savedValue: string;
  placeholder: string;
  emptyHint: string;
  saveLabel: string;
  confirmTitle: string;
  confirmBody: string;
  inputProps?: ComponentProps<typeof TextField.Root>;
  save: (value: string) => Promise<unknown>;
  setError: (msg: string | null) => void;
  mb?: string;
}) {
  const queryClient = useQueryClient();
  const { confirm, confirmDialog } = useConfirm();
  const [value, setValue] = useState(savedValue);
  // Tracked locally (rather than relying on the refetched prop) so the dirty/saved indicators
  // update the moment the mutation succeeds, not when the config query settles.
  const [lastSaved, setLastSaved] = useState(savedValue);
  const isDirty = value !== lastSaved;

  const mutation = useMutation({
    mutationFn: () => save(value),
    onSuccess: () => {
      setError(null);
      setLastSaved(value);
      void queryClient.invalidateQueries({ queryKey: ['config'] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const handleSave = () => {
    if (lastSaved) {
      confirm({
        title: confirmTitle,
        body: confirmBody,
        confirmLabel: 'Update',
        confirmColor: 'red',
        onConfirm: () => mutation.mutate(),
      });
    } else {
      mutation.mutate();
    }
  };

  const showSaved = mutation.isSuccess && !isDirty;

  return (
    <Flex direction="column" gap="2" mb={mb}>
      <Flex align="center" gap="1">
        <Text as="label" weight="bold" size="2">
          {label}
        </Text>
        <InfoPopover title={infoTitle}>{info}</InfoPopover>
      </Flex>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (isDirty) handleSave();
        }}
      >
        <Flex gap="2" align="center">
          <TextField.Root
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={placeholder}
            style={{ flex: 1 }}
            {...inputProps}
          />
          <Button type="submit" disabled={!isDirty} loading={mutation.isPending} >
            <IconPencil size={14} />
            {saveLabel}
          </Button>
        </Flex>
      </form>
      {isDirty ? (
        <Text size="1" color="orange">
          Unsaved changes — click &ldquo;{saveLabel}&rdquo; to apply.
        </Text>
      ) : showSaved ? (
        <Flex align="center" gap="1">
          <IconCheck size={14} color="var(--green-9)" />
          <Text size="1" color="green">
            Saved
          </Text>
        </Flex>
      ) : !lastSaved ? (
        <Text size="1" color="gray">
          {emptyHint}
        </Text>
      ) : null}
      {confirmDialog}
    </Flex>
  );
}
