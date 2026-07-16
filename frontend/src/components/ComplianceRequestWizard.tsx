import type { ReactNode } from 'react';
import Wizard from './Wizard';
import {ClientWizardPager, AdminWizardPager} from './ComplianceRequestWizardPager';
import { useNavigate } from 'react-router-dom';
import { useState } from 'react';

interface ComplianceRequestWizardProps {
  steps: ReactNode[];
  form: any;
  activeClasses: any;
  isAdminView: boolean;
  mode: string;
  setActionError: any;
  buildPayload: any;
  requestId: number | null;
}

function ComplianceRequestWizard({ steps, form, activeClasses, isAdminView, mode, setActionError, buildPayload, requestId }: ComplianceRequestWizardProps) {

  const [step, setStep] = useState(0);
  const stepTitles = ['Compliance Details', 'Run Selection', 'DER Details', 'Software Client Details'];


  const onError = (err: Error) => setActionError(err.message);
  const navigate = useNavigate();

  const wizardPager = isAdminView ?
    <AdminWizardPager
        step={step}
        stepCount={stepTitles.length}
        setStep={setStep}
        mode={mode}
        buildPayload={buildPayload}
        requestId={requestId}
        gotoComplianceRequests={() => navigate('/admin/compliance')}
        onError={onError}
      /> :
     <ClientWizardPager
        step={step}
        stepCount={stepTitles.length}
        form={form}
        activeClasses={activeClasses}
        setStep={setStep}
        mode={mode}
        buildPayload={buildPayload}
        requestId={requestId}
        gotoComplianceRequests={() => navigate('/compliance')}
        onError={onError}
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
