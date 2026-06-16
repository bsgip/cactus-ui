import { createBrowserRouter, type RouteObject } from 'react-router-dom';
import { Layout } from './components/Layout';
import { AdminPage } from './pages/Admin/AdminPage';
import { ConfigPage } from './pages/Config';
import { HomePage } from './pages/Home/HomePage';
import { ProceduresPage } from './pages/Procedures/ProceduresPage';
import { ProcedureYamlPage } from './pages/ProcedureYaml/ProcedureYamlPage';
import { RunGroupPage } from './pages/RunGroup/RunGroupPage';
import { RunsPage } from './pages/Runs/RunsPage';
import { RunsRedirect } from './pages/Runs/RunsRedirect';

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
      { path: 'config', element: <ConfigPage /> },
      { path: 'admin', element: <AdminPage /> },
    ],
  },
];

export const router = createBrowserRouter(routes);
