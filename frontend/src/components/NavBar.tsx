import { Anchor, Box, Button, Container, Group, Text } from '@mantine/core';
import { IconLogout } from '@tabler/icons-react';
import { Link } from 'react-router-dom';
import type { SessionResponse } from '../api/types';

export function NavBar({ session }: { session: SessionResponse }) {
  const isAdmin = session.permissions.includes('admin:all');

  return (
    <Box component="nav" bg="green.8" py="sm">
      <Container size="lg">
        <Group justify="space-between">
          <Group gap="md">
            <Anchor href="/" c="white" fz="xl" underline="never">
              🌵
            </Anchor>
            {session.username && <Text c="white">User: {session.username}</Text>}
          </Group>
          <Group gap="md">
            {isAdmin && (
              <>
                <Anchor component={Link} to="/admin" c="white">
                  Admin
                </Anchor>
                <Text c="white">|</Text>
                <Anchor component={Link} to="/admin/stats" c="white">
                  Stats
                </Anchor>
                <Text c="white">|</Text>
              </>
            )}
            <Anchor component={Link} to="/procedures" c="white">
              Procedures
            </Anchor>
            <Text c="white">|</Text>
            <Anchor component={Link} to="/runs" c="white">
              Runs
            </Anchor>
            <Text c="white">|</Text>
            <Anchor component={Link} to="/playlists" c="white">
              Playlists
            </Anchor>
            <Text c="white">|</Text>
            <Anchor component={Link} to="/config" c="white">
              Config
            </Anchor>
            <Button
              component="a"
              href="/logout"
              variant="outline"
              color="white"
              size="xs"
              leftSection={<IconLogout size={14} />}
            >
              Logout
            </Button>
          </Group>
        </Group>
      </Container>
    </Box>
  );
}
