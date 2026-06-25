import { Alert } from '@mantine/core';
import { useState } from 'react';

// Dismissible warning alert. The message comes from the BANNER_MESSAGE envvar and
// may contain HTML, so it's rendered via dangerouslySetInnerHTML.
export function Banner({ message }: { message: string | null | undefined }) {
  const [dismissed, setDismissed] = useState(false);

  if (!message || dismissed) {
    return null;
  }

  return (
    <Alert color="yellow" withCloseButton onClose={() => setDismissed(true)} mb="md" role="alert">
      <span dangerouslySetInnerHTML={{ __html: message }} />
    </Alert>
  );
}
