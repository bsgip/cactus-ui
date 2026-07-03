import { Box, Container } from '@radix-ui/themes';
import { Outlet } from 'react-router-dom';
import { UnauthenticatedError } from '../api/client';
import type { UnauthenticatedResponse } from '../api/types';
import { useSession } from '../hooks/useSession';
import { LoginPage } from '../pages/LoginPage';
import { ErrorAlert } from './ErrorAlert';
import { Footer } from './Footer';
import { NavBar } from './NavBar';
import { PageSpinner } from './PageSpinner';

export function Layout() {
  const { data: session, isPending, error } = useSession();

  if (isPending) {
    return <PageSpinner />;
  }

  if (error instanceof UnauthenticatedError) {
    const body = error.body as UnauthenticatedResponse | null;
    return <LoginPage loginBannerMessage={body?.login_banner_message ?? null} />;
  }

  if (error || !session) {
    return (
      <Container size="4">
        <Box px="4" py="6">
          <ErrorAlert message="Unable to communicate with test server. Please try refreshing the page or re-logging in." />
        </Box>
      </Container>
    );
  }

  return (
    <Box style={{ minHeight: '100vh' }}>
      <NavBar session={session} />
      <Container size="4">
        <Box px="4" py="6">
          <Outlet />
        </Box>
      </Container>
      <Footer session={session} />
    </Box>
  );
}
