import {
  Flex,
  Text,
} from '@radix-ui/themes';
import React from 'react';

import { InfoPopover } from './InfoPopover';

interface FieldHeaderProps {
  title: string;
  children: React.ReactNode;
};

function FieldHeader({title, children} : FieldHeaderProps) {
  return (
        <Flex align="center" gap="2">
          <Text as="div" size="2" weight="bold" mb="1" mt="1">
            {title}
          </Text>
          {children &&
            <InfoPopover>
              {children}
            </InfoPopover>
          }
        </Flex>
  );
};

export default FieldHeader
