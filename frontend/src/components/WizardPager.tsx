import { Flex, Button } from '@radix-ui/themes';

interface WizardPagerProps {
  step: number;
  stepCount: number;
  setStep: any;
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
