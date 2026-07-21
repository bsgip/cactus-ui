import { IconDownload, IconEye, IconPencil, IconTrash } from '@tabler/icons-react';
import { type ComplianceAction } from '../utils/complianceStatus';

import {
  IconButton,
} from '@radix-ui/themes';

const ACTION_META: Record<
  ComplianceAction,
  {
    icon: typeof IconPencil;
    color: React.ComponentProps<typeof IconButton>['color'];
    tooltip: string;
  }
> = {
  edit: { icon: IconPencil, color: 'blue', tooltip: 'Review / edit compliance request' },
  view: { icon: IconEye, color: 'gray', tooltip: 'View compliance request' },
  download: { icon: IconDownload, color: 'gray', tooltip: 'Download compliance report' },
  delete: { icon: IconTrash, color: 'red', tooltip: 'Delete compliance request (permanent)' },
};

function ActionButton({
  action,
  downloadHref,
  onClick,
}: {
  action: ComplianceAction;
  downloadHref: string;
  onClick: () => void;
}) {
  const { icon: Icon, color, tooltip } = ACTION_META[action];
  if (action === 'download') {
    return (
      <IconButton asChild variant="outline" color={color} title={tooltip}>
        <a href={downloadHref}>
          <Icon size={16} />
        </a>
      </IconButton>
    );
  }
  return (
    <IconButton variant="outline" color={color} title={tooltip} onClick={onClick}>
      <Icon size={16} />
    </IconButton>
  );
}

export default ActionButton;

