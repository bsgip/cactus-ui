import { Flex, Button } from '@radix-ui/themes';
import {Dispatch, SetStateAction} from 'react';

interface WizardPagerProps {
  step: number;
  stepCount: number;
  setStep: Dispatch<SetStateAction<number>>;
  children: React.ReactNode;
}

function WizardPager({ step, stepCount, setStep, children }: WizardPagerProps) {
  const isLastStep = step === stepCount - 1;

  return (
    <Flex justify="end" gap="2" wrap="wrap">
      {step > 0 && (
        <Button variant="soft" color="gray" onClick={() => setStep(step - 1)}>
          Back
        </Button>
      )}
      {!isLastStep && <Button onClick={() => setStep(step + 1)}>Next</Button>}

      {children}

    </Flex>
  );
}

export default WizardPager;
