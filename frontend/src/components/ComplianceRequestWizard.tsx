
import type { ReactNode } from 'react';
import Wizard from './Wizard';
import WizardPager from './WizardPager';

interface ComplianceRequestWizardProps {
  step: number;
  setStep: any;
  stepTitles: string[];
  steps: ReactNode[];
  form: any;
  activeClasses: any;
  isAdminView: boolean;
  mode: string;
  setActionError: any;
  buildPayload: any;
  requestId: number | null;
}

function ComplianceRequestWizard({ step, setStep, stepTitles, steps, form, activeClasses, isAdminView, mode, setActionError, buildPayload, requestId }: ComplianceRequestWizardProps) {

  const wizardPager = <WizardPager
        step={step}
        stepCount={stepTitles.length}
        form={form}
        activeClasses={activeClasses}
        setStep={setStep}
        isAdminView={isAdminView}
        mode={mode}
        setActionError={setActionError}
        buildPayload={buildPayload}
        requestId={requestId}
      />

  return (
    <Wizard
      step={step}
      setStep={setStep}
      stepTitles={stepTitles}
      steps={steps}
      wizardPager={wizardPager}
    />

  );
}

export default ComplianceRequestWizard;
