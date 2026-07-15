import type { ReactNode } from 'react';
import { Tabs, Flex, Button } from '@radix-ui/themes';
import { useNavigate } from 'react-router-dom';

import { FormState } from '../utils/complianceRequestWizard';
import {
  createComplianceRequest,
  updateComplianceRequest,
  adminUpdateComplianceRequest,
} from '../api/compliance';
import useMutationSafe from '../hooks/useMutationSafe';



function WizardStepper({stepTitles}: {stepTitles: string[]}) {

  return (
    <Tabs.List>
      {stepTitles.map((title: string, i: number) => (
        <Tabs.Trigger key={title} value={String(i)}>
          {i + 1}. {title}
        </Tabs.Trigger>
      ))}
    </Tabs.List>
  );
}

function WizardBody({steps} : {steps: ReactNode[]}) {
  let children: ReactNode[] = [];
  steps.forEach((stepComponent, i) => {
    children.push(
      <Tabs.Content value={'' + i} key={i}>
        {stepComponent}
      </Tabs.Content>)
  });
  return (
    <>
      {children}
    </>
  );
}

interface WizardPagerProps {
  step: number;
  stepCount: number;
  form: FormState;
  activeClasses: any;
  setStep: any;
  isAdminView: boolean;
  mode: string;
  setActionError: any;
  buildPayload: any;
  requestId: number|null;
}


function WizardPager({ step, stepCount, form, activeClasses, setStep, isAdminView, mode, setActionError, buildPayload, requestId }: WizardPagerProps) {
  const isLastStep = step === stepCount - 1;
  const submitDisabled = !form.witnessed_at || activeClasses.length === 0;

  const listPath = isAdminView ? '/admin/compliance' : '/compliance';
  const navigate = useNavigate();
  const onError = (err: Error) => setActionError(err.message);
  const goToList = () => navigate(listPath);
  const createMutation = useMutationSafe(
    () => createComplianceRequest(buildPayload()),
    goToList,
    onError
  );
  const updateMutation = useMutationSafe(
    () => updateComplianceRequest(requestId as number, buildPayload()),
    goToList,
    onError
  );
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

      {isLastStep && !isAdminView && mode === 'new' && (
        <Button
          disabled={submitDisabled}
          loading={createMutation.isPending}
          onClick={() => createMutation.mutate()}
        >
          Submit
        </Button>
      )}
      {isLastStep && !isAdminView && mode === 'edit' && (
        <Button
          disabled={submitDisabled}
          loading={updateMutation.isPending}
          onClick={() => updateMutation.mutate()}
        >
          Update
        </Button>
      )}
      {isLastStep && isAdminView && mode === 'edit' && (
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

interface WizardProps {
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

function Wizard({ step, setStep, stepTitles, steps, form, activeClasses, isAdminView, mode, setActionError, buildPayload, requestId }: WizardProps) {
  return (
    <>
      <Tabs.Root value={String(step)} onValueChange={(v) => setStep(Number(v))}>
        <WizardStepper stepTitles={stepTitles} />
        <WizardBody steps={steps} />
      </Tabs.Root>
      <WizardPager
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
    </>

  );
}

export default Wizard;
