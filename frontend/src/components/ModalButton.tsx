import { Modal, type ModalProps } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import type { ReactNode } from 'react';

interface ModalButtonProps {
  // Renders the trigger; call `open` to show the modal. Works for any control
  // (a Button, a Menu.Item, etc.), not just a plain button.
  trigger: (open: () => void) => ReactNode;
  title: ReactNode;
  size?: ModalProps['size'];
  // Modal body; receives `close` so its own actions can dismiss the modal.
  children: (close: () => void) => ReactNode;
}

// Pairs a trigger control with a Modal, wrapping the useDisclosure open/close skeleton.
export function ModalButton({ trigger, title, size, children }: ModalButtonProps) {
  const [opened, { open, close }] = useDisclosure(false);
  return (
    <>
      {trigger(open)}
      <Modal opened={opened} onClose={close} title={title} size={size}>
        {children(close)}
      </Modal>
    </>
  );
}
