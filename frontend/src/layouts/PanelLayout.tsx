import { useEffect, useState } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router';

import { useWebSocketBridge } from '@/api/websocketBridge';
import { usePageTitle } from '@/hooks/usePageTitle';
import { HttpUtil } from '@/utils';
import CommandPalette from '@/components/command-palette/CommandPalette';

// Mount the global websocket bridge *only* for the root panel owner.
// Its shared channel broadcasts global client and server data; it cannot
// safely be shared with reseller accounts until the hub is tenant-aware.
function OwnerWebSocketBridge() {
  useWebSocketBridge();
  return null;
}

export default function PanelLayout() {
  const { pathname } = useLocation();
  const [role, setRole] = useState<string | null>(null);
  const [checked, setChecked] = useState(false);
  usePageTitle();

  useEffect(() => {
    let active = true;
    void HttpUtil.get<{ role: string }>('/panel/api/admins/me', undefined, { silent: true })
      .then((result) => {
        if (!active) return;
        if (result.success && result.obj) setRole(result.obj.role);
        setChecked(true);
      });
    return () => { active = false; };
  }, []);

  if (!checked) return null;
  if (!role) return <div role="alert">Unable to verify panel identity. Please sign in again.</div>;
  if (role !== 'owner' && pathname !== '/admins') return <Navigate replace to="/admins" />;
  return (
    <>
      {role === 'owner' && <OwnerWebSocketBridge />}
      <Outlet />
      <CommandPalette />
    </>
  );
}
