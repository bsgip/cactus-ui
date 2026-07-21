import { Flex, Button } from '@radix-ui/themes';
import { useNavigate } from 'react-router-dom';
import { Dispatch, SetStateAction } from 'react';

import {
  type ComplianceRequestPayload,
  adminUpdateComplianceRequest,
} from '../api/compliance';
import useMutationSafe from '../hooks/useMutationSafe';
interface WizardPagerProps {
  step: number;
  stepCount: number;
  setStep: Dispatch<SetStateAction<number>>;
  mode: string;
  setActionError: Dispatch<SetStateAction<string | null>>;
  buildPayload: () => ComplianceRequestPayload;
  requestId: number | null;
}

function AdminWizardPager({ step, stepCount, setStep, mode, setActionError, buildPayload, requestId }: WizardPagerProps) {
  const isLastStep = step === stepCount - 1;

  const listPath = '/admin/compliance';
  const navigate = useNavigate();
  const onError = (err: Error) => setActionError(err.message);
  const goToList = () => navigate(listPath);
  const adminSaveMutation = useMutationSafe(
    () => adminUpdateComplianceRequest(requestId as number, 'under_review', buildPayload()),
    goToList,
    onError
  );
  const adminPushBackMutation = useMutationSafe(
    () => adminUpdateComplianceRequest(requestId as number, 'pushed_back', buildPayload()),
    goToList,
    onError
  );

  return (
    <Flex justify="end" gap="2" wrap="wrap">
      {step > 0 && (
        <Button variant="soft" color="gray" onClick={() => setStep(step - 1)}>
          Back
        </Button>
      )}
      {!isLastStep && <Button onClick={() => setStep(step + 1)}>Next</Button>}

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
            color="orange"
            loading={adminPushBackMutation.isPending}
            onClick={() => adminPushBackMutation.mutate()}
          >
            Push Back
          </Button>
          <form
            method="POST"
            action={`/admin/compliance/requests/${requestId}/finalise`}
            target="complianceFinaliseFrame"
            onSubmit={() => setTimeout(goToList, 500)}
            style={{ display: 'inline' }}
          >
            <Button type="submit" color="green">
              Finalise
            </Button>
          </form>
        </>
      )}
    </Flex>
  );
}

export default AdminWizardPager;
