import { IconButton, Tooltip } from '@radix-ui/themes';
import { IconCheck, IconCopy, IconX } from '@tabler/icons-react';
import { useState } from 'react';

const RESET_MS = 1500;

const TOOLTIPS = { idle: 'Copy', copied: 'Copied', failed: 'Copy failed' } as const;

// Ghost icon button that copies `value` to the clipboard, flipping to a green check briefly to
// confirm the copy landed (or a red cross if the clipboard is unavailable, e.g. over plain HTTP).
export function CopyButton({ value }: { value: string }) {
  const [state, setState] = useState<keyof typeof TOOLTIPS>('idle');

  const handleClick = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState('copied');
    } catch {
      setState('failed');
    }
    setTimeout(() => setState('idle'), RESET_MS);
  };

  return (
    <Tooltip content={TOOLTIPS[state]}>
      <IconButton
        type="button"
        size="1"
        variant="ghost"
        color="gray"
        onClick={() => void handleClick()}
      >
        {state === 'copied' ? (
          <IconCheck size={14} color="var(--green-9)" />
        ) : state === 'failed' ? (
          <IconX size={14} color="var(--red-9)" />
        ) : (
          <IconCopy size={14} />
        )}
      </IconButton>
    </Tooltip>
  );
}
