import { createBrowserRouter, type RouteObject } from 'react-router-dom';
import { Layout } from './components/Layout';
import { AdminPage } from './pages/AdminPage';
import { AdminStatsPage } from './pages/AdminStats/AdminStatsPage';
import { AdminCompliancePage } from './pages/AdminCompliancePage';
import { CompliancePage } from './pages/CompliancePage';
import { ComplianceRequestPage } from './pages/ComplianceRequestPage';
import { ConfigPage } from './pages/Config/ConfigPage';
import { HomePage } from './pages/HomePage';
import { NotFoundPage } from './pages/NotFoundPage';
import { ProceduresPage } from './pages/ProceduresPage';
import { PlaylistsPage } from './pages/Playlists/PlaylistsPage';
import { PlaylistsRedirect } from './pages/Playlists/PlaylistsRedirect';
import { ProcedureYamlPage } from './pages/ProcedureYamlPage';
import { RunGroupPage } from './pages/RunGroupPage';
import { RunsPage } from './pages/Runs/RunsPage';
import { RunsRedirect } from './pages/Runs/RunsRedirect';
import { RunStatusPage } from './pages/RunStatus/RunStatusPage';

export const routes: RouteObject[] = [
  {
    path: '/',
    element: <Layout />,
    children: [
      { index: true, element: <HomePage /> },
      { path: 'procedures', element: <ProceduresPage /> },
      { path: 'procedure/:testProcedureId', element: <ProcedureYamlPage /> },
      { path: 'runs', element: <RunsRedirect /> },
      { path: 'group/:runGroupId/runs', element: <RunsPage isAdminView={false} /> },
      { path: 'admin/group/:runGroupId/runs', element: <RunsPage isAdminView={true} /> },
      { path: 'group/:runGroupId', element: <RunGroupPage isAdminView={false} /> },
      { path: 'admin/group/:runGroupId', element: <RunGroupPage isAdminView={true} /> },
      { path: 'run/:runId', element: <RunStatusPage isAdminView={false} /> },
      { path: 'admin/run/:runId', element: <RunStatusPage isAdminView={true} /> },
      { path: 'playlists', element: <PlaylistsRedirect /> },
      { path: 'group/:runGroupId/playlists', element: <PlaylistsPage /> },
      { path: 'config', element: <ConfigPage /> },
      { path: 'compliance', element: <CompliancePage /> },
      { path: 'compliance-request', element: <ComplianceRequestPage isAdminView={false} /> },
      { path: 'admin', element: <AdminPage /> },
      { path: 'admin/stats', element: <AdminStatsPage /> },
      { path: 'admin/compliance', element: <AdminCompliancePage /> },
      { path: 'admin/compliance-request', element: <ComplianceRequestPage isAdminView={true} /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
];

export const router = createBrowserRouter(routes);
