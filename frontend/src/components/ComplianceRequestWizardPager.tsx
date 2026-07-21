import { Button } from '@radix-ui/themes';

import {
  createComplianceRequest,
  updateComplianceRequest,
  adminUpdateComplianceRequest,
  finaliseComplianceRequest,
} from '../api/compliance';
import useMutationSafe from '../hooks/useMutationSafe';
import { FormState } from '../utils/complianceRequestForm';
import WizardPager from './WizardPager';

interface ClientWizardPagerProps {
  step: number;
  stepCount: number;
  form: FormState;
  activeClasses: any;
  setStep: any;
  mode: string;
  buildPayload: any;
  requestId: number | null;
  gotoComplianceRequests: any;
  onError: any;
}

export function ClientWizardPager({ step, stepCount, form, activeClasses, setStep, mode, buildPayload, requestId, gotoComplianceRequests, onError }: ClientWizardPagerProps) {
  const isLastStep = step === stepCount - 1;
  const submitDisabled = !form.witnessed_at || activeClasses.length === 0;

  const createMutation = useMutationSafe(
    () => createComplianceRequest(buildPayload()),
    gotoComplianceRequests,
    onError
  );
  const updateMutation = useMutationSafe(
    () => updateComplianceRequest(requestId as number, buildPayload()),
    gotoComplianceRequests,
    onError
  );

  return (
    <WizardPager step={step} stepCount={stepCount} setStep={setStep}>
      {isLastStep && mode === 'new' && (
        <Button
          disabled={submitDisabled}
          loading={createMutation.isPending}
          onClick={() => createMutation.mutate()}
        >
          Submit
        </Button>
      )}
      {isLastStep && mode === 'edit' && (
        <Button
          disabled={submitDisabled}
          loading={updateMutation.isPending}
          onClick={() => updateMutation.mutate()}
        >
          Update
        </Button>
      )}
    </WizardPager>
  );
}

interface AdminWizardPagerProps {
  step: number;
  stepCount: number;
  setStep: any;
  mode: string;
  buildPayload: any;
  requestId: number | null;
  gotoComplianceRequests: any;
  onError: any;
}

export function AdminWizardPager({ step, stepCount, setStep, mode, buildPayload, requestId, gotoComplianceRequests, onError }: AdminWizardPagerProps) {
  const isLastStep = step === stepCount - 1;

  const adminSaveMutation = useMutationSafe(
    () => adminUpdateComplianceRequest(requestId as number, 'under_review', buildPayload()),
    gotoComplianceRequests,
    onError
  );
  const adminPushBackMutation = useMutationSafe(
    () => adminUpdateComplianceRequest(requestId as number, 'pushed_back', buildPayload()),
    gotoComplianceRequests,
    onError
  );
  const adminFinaliseMutation = useMutationSafe(
    () => finaliseComplianceRequest(requestId as number),
    gotoComplianceRequests,
    onError
  );

  return (
    <WizardPager step={step} stepCount={stepCount} setStep={setStep}>
      {isLastStep && mode === 'edit' && (
        <>
          <Button
            variant="soft"
            loading={adminSaveMutation.isPending}
            onClick={() => adminSaveMutation.mutate()}
          >
            Save &amp; Exit
          </Button>
          <Button
            variant="soft"
            loading={adminPushBackMutation.isPending}
            onClick={() => adminPushBackMutation.mutate()}
          >
            Push Back
          </Button>
          <Button
              color="green"
              loading={adminFinaliseMutation.isPending}
              onClick={() => adminFinaliseMutation.mutate()} >
            Finalise
          </Button>
        </>
      )}
    </WizardPager>
  );
}

