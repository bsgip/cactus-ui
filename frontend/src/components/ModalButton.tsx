import { Dialog } from '@radix-ui/themes';
import type { ReactNode } from 'react';
import { useDisclosure } from '../hooks/useDisclosure';

type Size = 'sm' | 'md' | 'lg' | 'xl';

interface ModalButtonProps {
  // Renders the trigger; call `open` to show the modal. Works for any control
  // (a Button, a DropdownMenu.Item, etc.), not just a plain button.
  trigger: (open: () => void) => ReactNode;
  title: ReactNode;
  size?: Size;
  // Modal body; receives `close` so its own actions can dismiss the modal.
  children: (close: () => void) => ReactNode;
}

const MAX_WIDTH: Record<Size, string> = {
  sm: '400px',
  md: '500px',
  lg: '600px',
  xl: '800px',
};

// Pairs a trigger control with a Dialog, wrapping the open/close skeleton.
export function ModalButton({ trigger, title, size, children }: ModalButtonProps) {
  const [opened, { open, close }] = useDisclosure(false);
  return (
    <>
      {trigger(open)}
      <Dialog.Root open={opened} onOpenChange={(o) => !o && close()}>
        <Dialog.Content maxWidth={size ? MAX_WIDTH[size] : undefined}>
          <Dialog.Title>{title}</Dialog.Title>
          {children(close)}
        </Dialog.Content>
      </Dialog.Root>
    </>
  );
}
