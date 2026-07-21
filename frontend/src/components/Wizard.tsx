import { type ReactNode, Dispatch, SetStateAction } from 'react';
import { Tabs } from '@radix-ui/themes';


function WizardStepper({ stepTitles }: { stepTitles: string[] }) {
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


function WizardBody({ steps }: { steps: ReactNode[] }) {
  const children: ReactNode[] = [];
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


interface WizardProps {
  step: number;
  setStep: Dispatch<SetStateAction<number>>;
  stepTitles: string[];
  steps: ReactNode[];
  wizardPager: ReactNode;
}

function Wizard({ step, setStep, stepTitles, steps, wizardPager }: WizardProps) {
  return (
    <>
      <Tabs.Root value={String(step)} onValueChange={(v) => setStep(Number(v))}>
        <WizardStepper stepTitles={stepTitles} />
        <WizardBody steps={steps} />
      </Tabs.Root>
      {wizardPager}
    </>

  );
}

export default Wizard;
