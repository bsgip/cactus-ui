import { Button, Container, DropdownMenu, Flex, Link, Text } from '@radix-ui/themes';
import { IconLogout } from '@tabler/icons-react';
import { Fragment } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import type { SessionResponse } from '../api/types';


function AdminMenu() {
  // Admin-only destinations, collapsed into a single "Admin" dropdown.
  const ADMIN_LINKS = [
    { to: '/admin', label: 'Manage Users' },
    { to: '/admin/compliance', label: 'Compliance' },
    { to: '/admin/stats', label: 'Platform Stats' },
  ];

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger>
        <Button style={{ color: 'white', textDecorationColor: 'white' }} size="3">
          Admin
          <DropdownMenu.TriggerIcon />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Content>
        {ADMIN_LINKS.map((link, i) => (
          <Fragment key={link.to}>
            {/* Divider before the last item (Platform Stats), matching the legacy nav. */}
            {i === ADMIN_LINKS.length - 1 && <DropdownMenu.Separator />}
            <DropdownMenu.Item asChild>
              <RouterLink to={link.to}>{link.label}</RouterLink>
            </DropdownMenu.Item>
          </Fragment>
        ))}
      </DropdownMenu.Content>
    </DropdownMenu.Root>
  );
}

function NavLinks() {
  const NAV_LINKS = [
    { to: '/procedures', label: 'Procedures' },
    { to: '/runs', label: 'Runs' },
    { to: '/playlists', label: 'Playlists' },
    { to: '/compliance', label: 'Compliance' },
    { to: '/config', label: 'Config' },
  ];

  return (
    <>
      {NAV_LINKS.map((link) => (
        <Fragment key={link.to}>
          <Link asChild style={{ color: 'white', textDecorationColor: 'white' }}>
            <RouterLink to={link.to}>{link.label}</RouterLink>
          </Link>
        </Fragment>
      ))}
    </>
  );
}


export function NavBar({ session }: { session: SessionResponse }) {
  const isAdmin = session.permissions.includes('admin:all');

  return (
    <nav style={{ backgroundColor: 'var(--accent-9)', padding: 'var(--space-3) 0' }}>
      <Container size="4">
        <Flex justify="between" align="center" px="5">
          <Flex gap="3" align="center">
            <Link href="/" underline="none" style={{ color: 'white'}} size="6">
              🌵 CACTUS
            </Link>
          </Flex>
          <Flex gap="5" align="center">
            {isAdmin && <AdminMenu />}
            <NavLinks />
          </Flex>
          <Flex gap="3" align="center">
            {session.username && <Text style={{color: 'white'}}>{session.username}</Text>}
            <Button asChild variant="outline" size="2" style={{ color: 'white', border: '1px solid white' }}>
              <a href="/logout">
                <IconLogout size={20} />
                Logout
              </a>
            </Button>
          </Flex>
        </Flex>
      </Container>
    </nav>
  );
}
