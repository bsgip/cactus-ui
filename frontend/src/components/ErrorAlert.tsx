import { Callout } from '@radix-ui/themes';
import { IconAlertTriangle } from '@tabler/icons-react';

export function ErrorAlert({ message }: { message: string }) {
  return (
    <Callout.Root color="red" role="alert" mb="3">
      <Callout.Icon>
        <IconAlertTriangle size={16} />
      </Callout.Icon>
      <Callout.Text>{message}</Callout.Text>
    </Callout.Root>
  );
}
