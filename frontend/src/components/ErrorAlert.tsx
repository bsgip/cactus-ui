import { Alert } from '@mantine/core';
import { IconAlertTriangle } from '@tabler/icons-react';

export function ErrorAlert({ message }: { message: string }) {
  return (
    <Alert color="red" icon={<IconAlertTriangle size={16} />} mb="md" role="alert">
      {message}
    </Alert>
  );
}
