import { Alert } from '@mantine/core';
import { useState } from 'react';

// Port of banner.html: dismissible warning alert. The message comes from the
// BANNER_MESSAGE envvar and was rendered with `| safe` in Jinja, so it may contain HTML.
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
