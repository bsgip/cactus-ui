import { createBrowserRouter, type RouteObject } from 'react-router-dom';
import { Layout } from './components/Layout';
import { HomePage } from './pages/Home/HomePage';
import { ProceduresPage } from './pages/Procedures/ProceduresPage';
import { ProcedureYamlPage } from './pages/ProcedureYaml/ProcedureYamlPage';

export const routes: RouteObject[] = [
  {
    path: '/',
    element: <Layout />,
    children: [
      { index: true, element: <HomePage /> },
      { path: 'procedures', element: <ProceduresPage /> },
      { path: 'procedure/:testProcedureId', element: <ProcedureYamlPage /> },
    ],
  },
];

export const router = createBrowserRouter(routes);
