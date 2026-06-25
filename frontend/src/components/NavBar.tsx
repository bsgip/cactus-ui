import { Button, Container, Flex, Link, Text } from '@radix-ui/themes';
import { IconLogout } from '@tabler/icons-react';
import { Link as RouterLink } from 'react-router-dom';
import type { SessionResponse } from '../api/types';

const white = { color: 'white' };

export function NavBar({ session }: { session: SessionResponse }) {
  const isAdmin = session.permissions.includes('admin:all');

  return (
    <nav style={{ backgroundColor: 'var(--green-9)', padding: '8px 0' }}>
      <Container size="4">
        <Flex justify="between" align="center" px="4">
          <Flex gap="3" align="center">
            <Link href="/" underline="none" style={{ ...white, fontSize: '1.5rem' }}>
              🌵
            </Link>
            {session.username && <Text style={white}>User: {session.username}</Text>}
          </Flex>
          <Flex gap="3" align="center">
            {isAdmin && (
              <>
                <Link asChild style={white}>
                  <RouterLink to="/admin">Admin</RouterLink>
                </Link>
                <Text style={white}>|</Text>
                <Link asChild style={white}>
                  <RouterLink to="/admin/stats">Stats</RouterLink>
                </Link>
                <Text style={white}>|</Text>
              </>
            )}
            <Link asChild style={white}>
              <RouterLink to="/procedures">Procedures</RouterLink>
            </Link>
            <Text style={white}>|</Text>
            <Link asChild style={white}>
              <RouterLink to="/runs">Runs</RouterLink>
            </Link>
            <Text style={white}>|</Text>
            <Link asChild style={white}>
              <RouterLink to="/playlists">Playlists</RouterLink>
            </Link>
            <Text style={white}>|</Text>
            <Link asChild style={white}>
              <RouterLink to="/config">Config</RouterLink>
            </Link>
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
