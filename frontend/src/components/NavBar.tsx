import { Button, Container, Flex, Link, Text } from '@radix-ui/themes';
import { IconLogout } from '@tabler/icons-react';
import { Fragment } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import type { SessionResponse } from '../api/types';

const white = { color: 'white' };

const NAV_LINKS = [
  { to: '/procedures', label: 'Procedures' },
  { to: '/runs', label: 'Runs' },
  { to: '/playlists', label: 'Playlists' },
  { to: '/config', label: 'Config' },
];

const ADMIN_LINKS = [
  { to: '/admin', label: 'Admin' },
  { to: '/admin/stats', label: 'Stats' },
];

export function NavBar({ session }: { session: SessionResponse }) {
  const isAdmin = session.permissions.includes('admin:all');
  const links = isAdmin ? [...ADMIN_LINKS, ...NAV_LINKS] : NAV_LINKS;

  return (
    <nav style={{ backgroundColor: 'var(--accent-9)', padding: '8px 0' }}>
      <Container size="4">
        <Flex justify="between" align="center" px="4">
          <Flex gap="3" align="center">
            <Link href="/" underline="none" style={{ ...white, fontSize: '1.5rem' }}>
              🌵
            </Link>
            {session.username && <Text style={white}>User: {session.username}</Text>}
          </Flex>
          <Flex gap="3" align="center">
            {links.map((link, i) => (
              <Fragment key={link.to}>
                {i > 0 && <Text style={white}>|</Text>}
                <Link asChild style={white}>
                  <RouterLink to={link.to}>{link.label}</RouterLink>
                </Link>
              </Fragment>
            ))}
            <Button asChild variant="outline" size="1" style={white}>
              <a href="/logout">
                <IconLogout size={14} />
                Logout
              </a>
            </Button>
          </Flex>
        </Flex>
      </Container>
    </nav>
  );
}
