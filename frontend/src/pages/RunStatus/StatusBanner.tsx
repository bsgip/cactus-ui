import { IconClock } from '@tabler/icons-react';
import { useEffect, useState } from 'react';
import type { StepEventStatus } from '../../api/types';
import { activeStep, allStepsComplete } from './statusHelpers';

interface Props {
  stepStatus: Record<string, StepEventStatus> | null;
}

// Fixed bottom bar: a live wall clock and the currently-active step.
export function StatusBanner({ stepStatus }: Props) {
  const [clock, setClock] = useState(() => new Date().toTimeString().slice(0, 8));

  useEffect(() => {
    const id = setInterval(() => setClock(new Date().toTimeString().slice(0, 8)), 1000);
    return () => clearInterval(id);
  }, []);

  const active = activeStep(stepStatus);
  const allComplete = allStepsComplete(stepStatus);

  return (
    <div
      style={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        zIndex: 1050,
        background: allComplete ? 'var(--mantine-color-green-8)' : '#212529',
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
      <span style={{ color: allComplete ? 'rgba(255,255,255,0.6)' : '#6c757d' }}>|</span>
      <span style={{ color: active || allComplete ? '#fff' : '#adb5bd' }}>
        {active
          ? `Step ${active.index}: ${active.name}`
          : allComplete
            ? 'All steps complete'
            : 'No active step'}
      </span>
    </div>
  );
}
