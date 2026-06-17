import { IconClock } from '@tabler/icons-react';
import { useEffect, useState } from 'react';
import type { StepEventStatus } from '../../api/types';
import { activeStep } from './statusHelpers';

interface Props {
  stepStatus: Record<string, StepEventStatus> | null;
}

// Fixed bottom bar from run_status.html: a live wall clock and the currently-active step.
export function StatusBanner({ stepStatus }: Props) {
  const [clock, setClock] = useState(() => new Date().toTimeString().slice(0, 8));

  useEffect(() => {
    const id = setInterval(() => setClock(new Date().toTimeString().slice(0, 8)), 1000);
    return () => clearInterval(id);
  }, []);

  const active = activeStep(stepStatus);

  return (
    <div
      style={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        zIndex: 1050,
        background: '#212529',
        color: '#fff',
        padding: '8px 20px',
        display: 'flex',
        alignItems: 'center',
        gap: 20,
        fontFamily: 'monospace',
        fontSize: '0.95rem',
      }}
    >
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        <IconClock size={16} /> {clock}
      </span>
      <span style={{ color: '#6c757d' }}>|</span>
      <span style={{ color: active ? '#fff' : '#adb5bd' }}>
        {active ? `Step ${active.index}: ${active.name}` : 'No active step'}
      </span>
    </div>
  );
}
