import { AlertDialog, Button, Flex } from '@radix-ui/themes';
import { useCallback, useState, type ReactNode } from 'react';

interface ConfirmOptions {
  title: ReactNode;
  // Optional explanatory body shown above the action buttons.
  body?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  // Radix accent for the confirm button (e.g. "red" for destructive actions).
  confirmColor?: React.ComponentProps<typeof Button>['color'];
  onConfirm: () => void;
}

// Imperative replacement for @mantine/modals modals.openConfirmModal. Render
// `confirmDialog` once, then call `confirm({...})` to open it.
export function useConfirm() {
  const [options, setOptions] = useState<ConfirmOptions | null>(null);

  const confirm = useCallback((opts: ConfirmOptions) => setOptions(opts), []);
  const close = useCallback(() => setOptions(null), []);

  const confirmDialog = (
    <AlertDialog.Root open={options !== null} onOpenChange={(open) => !open && close()}>
      <AlertDialog.Content maxWidth="450px">
        <AlertDialog.Title>{options?.title}</AlertDialog.Title>
        {options?.body && <AlertDialog.Description>{options.body}</AlertDialog.Description>}
        <Flex gap="3" mt="4" justify="end">
          <AlertDialog.Cancel>
            <Button variant="soft" color="gray">
              {options?.cancelLabel ?? 'Cancel'}
            </Button>
          </AlertDialog.Cancel>
          <AlertDialog.Action>
            <Button
              color={options?.confirmColor}
              onClick={() => {
                options?.onConfirm();
                close();
              }}
            >
              {options?.confirmLabel ?? 'Confirm'}
            </Button>
          </AlertDialog.Action>
        </Flex>
      </AlertDialog.Content>
    </AlertDialog.Root>
  );

  return { confirm, confirmDialog };
}
