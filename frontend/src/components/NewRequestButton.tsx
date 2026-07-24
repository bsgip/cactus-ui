import {
  Button,
} from '@radix-ui/themes';
import { Link as RouterLink } from 'react-router-dom';
import { IconPlus } from '@tabler/icons-react';

function NewRequestButton({requestPath}: {requestPath: string}) {
return (
      <Button asChild size="3">
        <RouterLink to={requestPath}>
          <IconPlus size={16} /> New Request
        </RouterLink>
      </Button>
    );
}

export default NewRequestButton;

