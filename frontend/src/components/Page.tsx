import { ReactNode } from 'react';
import { Heading } from '@radix-ui/themes';

import PageBanner from './PageBanner';


interface PageProps {
  title: string;
  includeBanner: boolean;
  children: ReactNode;
};

function Page({title, includeBanner, children}: PageProps) {
  return (
    <>
      {includeBanner && <PageBanner />}
      <Heading as="h2" size="6" mb="7">
        {title}
      </Heading>
      {children}
    </>
  );
}

export default Page;

