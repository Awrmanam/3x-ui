import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Card, Col, ConfigProvider, Form, Input, InputNumber, Layout, Modal, Popconfirm, Row,
  Select, Space, Spin, Switch, Table, Tag, Typography, message,
} from 'antd';
import { useTheme } from '@/hooks/useTheme';
import AppSidebar from '@/layouts/AppSidebar';
import { HttpUtil } from '@/utils';

type Role = 'owner' | 'sudo' | 'admin' | 'reseller' | 'custom';
type Scope = 'none' | 'own' | 'assigned' | 'own_or_assigned' | 'all';
type Staff = { userId: number; username: string; role: Role; enabled: boolean };
type Identity = { id: number; username: string; role: Role };
type Permission = { userId: number; action: string; scope: Scope };
type Assignment = { userId: number; inboundId: number; canCreate: boolean };
type InboundOption = { id: number; remark: string; protocol: string; port: number };
type SubProfile = {
  title: string;
  supportId: string;
  supportUrl: string;
  remarkTemplate: string;
  shareLinkTemplate: string;
  pageTemplate: string;
  subscriptionBaseUrl: string;
};
type CreateInput = { username: string; password: string; role: Role; enabled: boolean };

const base = '/panel/api/admins';
const roles: Role[] = ['sudo', 'admin', 'reseller', 'custom'];
const scopes: Scope[] = ['none', 'own', 'assigned', 'own_or_assigned', 'all'];
const permissionActions = [
  'admins.read', 'inbounds.read', 'inbounds.create', 'inbounds.update', 'inbounds.delete',
  'clients.read', 'clients.create', 'clients.update', 'clients.delete', 'clients.reset_traffic',
  'subscriptions.read', 'subscriptions.manage', 'templates.manage', 'hosts.read',
  'hosts.manage', 'nodes.read', 'nodes.manage', 'traffic.read', 'settings.read',
  'settings.manage', 'routing.manage', 'tokens.manage', 'backups.export',
  'backups.restore', 'system.read', 'system.manage', 'audit.read',
] as const;

const emptyProfile: SubProfile = {
  title: '', supportId: '', supportUrl: '', remarkTemplate: '',
  shareLinkTemplate: '', pageTemplate: '', subscriptionBaseUrl: '',
};

export default function AdminsPage() {
  const { antdThemeConfig } = useTheme();
  const [messageApi, messageHolder] = message.useMessage();
  const [createForm] = Form.useForm<CreateInput>();
  const [me, setMe] = useState<Identity | null>(null);
  const [members, setMembers] = useState<Staff[]>([]);
  const [inbounds, setInbounds] = useState<InboundOption[]>([]);
  const [selectedID, setSelectedID] = useState<number | null>(null);
  const [editRole, setEditRole] = useState<Role>('reseller');
  const [editEnabled, setEditEnabled] = useState(false);
  const [resetPassword, setResetPassword] = useState('');
  const [overrides, setOverrides] = useState<Record<string, Scope>>({});
  const [assignments, setAssignments] = useState<Record<number, boolean>>({});
  const [profile, setProfile] = useState<SubProfile>(emptyProfile);
  const [createVisible, setCreateVisible] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const isOwner = me?.role === 'owner';
  const selected = useMemo(
    () => members.find((m) => m.userId === selectedID) ?? null,
    [members, selectedID],
  );
  const profileTarget = isOwner ? selectedID : me?.id;

  const loadIdentity = useCallback(async () => {
    setLoading(true);
    const result = await HttpUtil.get<Identity>(`${base}/me`, undefined, { silent: true });
    if (result.success && result.obj) setMe(result.obj);
    else messageApi.error(result.msg || 'Unable to load account identity');
    setLoading(false);
  }, [messageApi]);

  const refreshMembers = useCallback(async () => {
    const result = await HttpUtil.get<Staff[]>(`${base}/list`, undefined, { silent: true });
    if (result.success) setMembers(result.obj ?? []);
    else messageApi.error(result.msg || 'Unable to list staff accounts');
  }, [messageApi]);

  useEffect(() => { void loadIdentity(); }, [loadIdentity]);

  useEffect(() => {
    if (!me || !isOwner) return;
    void refreshMembers();
    void HttpUtil.get<InboundOption[]>('/panel/api/inbounds/options', undefined, { silent: true })
      .then((response) => { if (response.success) setInbounds(response.obj ?? []); });
  }, [me, isOwner, refreshMembers]);

  useEffect(() => {
    if (!me) return;
    const userID = isOwner ? selectedID : me.id;
    if (!userID) return;
    const profileURL = isOwner ? `${base}/${userID}/profile` : `${base}/me/profile`;
    void HttpUtil.get<SubProfile>(profileURL, undefined, { silent: true }).then((response) => {
      if (response.success && response.obj) {
        const p = response.obj;
        setProfile({ ...emptyProfile, ...p });
      } else setProfile(emptyProfile);
    });
    if (!isOwner) return;
    const member = members.find((m) => m.userId === userID);
    if (member) { setEditRole(member.role); setEditEnabled(member.enabled); }
    setResetPassword('');
    void HttpUtil.get<Permission[]>(`${base}/${userID}/permissions`, undefined, { silent: true })
      .then((response) => {
        const next: Record<string, Scope> = {};
        for (const grant of response.obj ?? []) next[grant.action] = grant.scope;
        setOverrides(next);
      });
    void HttpUtil.get<Assignment[]>(`${base}/${userID}/inbounds`, undefined, { silent: true })
      .then((response) => {
        const next: Record<number, boolean> = {};
        for (const grant of response.obj ?? []) next[grant.inboundId] = grant.canCreate;
        setAssignments(next);
      });
  }, [me, isOwner, selectedID, members]);

  const exec = useCallback(async (operation: () => Promise<{ success: boolean; msg: string }>, success: string) => {
    setSaving(true);
    try {
      const response = await operation();
      if (!response.success) messageApi.error(response.msg || 'Operation failed');
      else messageApi.success(success);
      return response.success;
    } finally { setSaving(false); }
  }, [messageApi]);

  async function createUser(values: CreateInput) {
    const ok = await exec(
      () => HttpUtil.post(`${base}/create`, values, { silent: true }),
      'Account created',
    );
    if (ok) { setCreateVisible(false); createForm.resetFields(); await refreshMembers(); }
  }

  async function updateUser() {
    if (selectedID == null) return;
    const payload: Record<string, unknown> = { role: editRole, enabled: editEnabled };
    if (resetPassword) payload.password = resetPassword;
    const ok = await exec(
      () => HttpUtil.post(`${base}/${selectedID}/update`, payload, { silent: true }),
      'Account updated and old sessions revoked',
    );
    if (ok) { setResetPassword(''); await refreshMembers(); }
  }

  async function savePermissions() {
    if (selectedID == null) return;
    const permissions = Object.entries(overrides)
      .filter(([, scope]) => scope !== undefined)
      .map(([action, scope]) => ({ action, scope }));
    await exec(
      () => HttpUtil.post(`${base}/${selectedID}/permissions`, { permissions }, { silent: true }),
      'Permissions updated; sessions revoked',
    );
  }

  async function saveAssignments() {
    if (selectedID == null) return;
    const rows = Object.entries(assignments).map(([inboundId, canCreate]) => ({
      inboundId: Number(inboundId), canCreate,
    }));
    await exec(
      () => HttpUtil.post(`${base}/${selectedID}/inbounds`, { inbounds: rows }, { silent: true }),
      'Inbound assignments saved',
    );
  }

  async function saveProfile() {
    if (!profileTarget) return;
    const endpoint = isOwner ? `${base}/${profileTarget}/profile` : `${base}/me/profile`;
    await exec(() => HttpUtil.post(endpoint, profile, { silent: true }), 'Profile saved');
  }

  function inputField(key: keyof SubProfile, label: string, placeholder = '') {
    return (
      <Col xs={24} md={12} key={key}>
        <Typography.Text>{label}</Typography.Text>
        <Input value={profile[key]} placeholder={placeholder}
          onChange={(e) => setProfile((old) => ({ ...old, [key]: e.target.value }))}
          maxLength={256} />
      </Col>
    );
  }

  return (
    <ConfigProvider theme={antdThemeConfig}>
      {messageHolder}
      <Layout>
        {isOwner ? <AppSidebar /> : (
          <Layout.Sider theme="light" width={190} style={{ padding: 16 }}>
            <Typography.Text strong>Reseller Panel</Typography.Text>
            <Button block style={{ marginTop: 24 }}
              onClick={() => { void HttpUtil.post('/logout', undefined, { silent: true })
                .then(() => { window.location.href = window.X_UI_BASE_PATH || '/'; }); }}>
              Logout
            </Button>
          </Layout.Sider>
        )}
        <Layout className="content-shell">
          <Layout.Content id="content-layout" className="content-area">
            <Space orientation="vertical" size="large" style={{ width: '100%' }}>
              <Typography.Title level={3}>Administrators & resellers</Typography.Title>
              <Alert type="warning" showIcon
                title="Safe rollout"
                description="Staff accounts can sign in and maintain their profiles, but legacy client and inbound APIs remain blocked until tenant isolation and subscription delivery are fully integrated. Profile templates are stored but not yet served to customers." />
              {loading ? <Spin /> : !me ? (
                <Alert type="error" title="Account identity could not be loaded" />
              ) : (
                <>
                  <Card>
                    <Space>
                      <Tag color={isOwner ? 'green' : 'blue'}>{me.role}</Tag>
                      <Typography.Text strong>{me.username}</Typography.Text>
                      <Typography.Text type="secondary">ID #{me.id}</Typography.Text>
                    </Space>
                  </Card>

                  {isOwner && (
                    <>
                      <Card title="Staff accounts"
                        extra={<Button type="primary" onClick={() => { createForm.resetFields(); setCreateVisible(true); }}>Create administrator</Button>}>
                        <Table<Staff> size="small" rowKey="userId" pagination={{ pageSize: 10 }}
                          dataSource={members}
                          rowSelection={{
                            type: 'radio',
                            selectedRowKeys: selectedID == null ? [] : [selectedID],
                            onChange: (ids) => setSelectedID(Number(ids[0])),
                          }}
                          columns={[
                            { title: 'Username', dataIndex: 'username', key: 'username' },
                            { title: 'Role', dataIndex: 'role', key: 'role' },
                            { title: 'Status', key: 'enabled', render: (_, row) => row.enabled ? <Tag color="green">Enabled</Tag> : <Tag>Disabled</Tag> },
                            { title: 'Account ID', dataIndex: 'userId', key: 'userId' },
                          ]}
                        />
                      </Card>
                      {selected && (
                        <Card title={`Manage ${selected.username}`}>
                          <Row gutter={[16, 16]}>
                            <Col xs={24} md={8}>
                              <Typography.Text>Role preset</Typography.Text>
                              <Select value={editRole} style={{ width: '100%' }}
                                onChange={setEditRole}
                                options={roles.map((role) => ({ label: role.toUpperCase(), value: role }))} />
                            </Col>
                            <Col xs={24} md={8}>
                              <Typography.Text>Account enabled</Typography.Text>
                              <div><Switch checked={editEnabled} onChange={setEditEnabled} /></div>
                            </Col>
                            <Col xs={24} md={8}>
                              <Typography.Text>New password (optional)</Typography.Text>
                              <Input.Password value={resetPassword} onChange={(e) => setResetPassword(e.target.value)}
                                autoComplete="new-password" placeholder="Minimum 12 characters" />
                            </Col>
                            <Col span={24}><Button loading={saving} type="primary" onClick={() => void updateUser()}>Save account</Button></Col>
                          </Row>
                        </Card>
                      )}
                      {selected && (
                        <Card title="Granular permission overrides"
                          extra={<Button loading={saving} type="primary" onClick={() => void savePermissions()}>Save permissions</Button>}>
                          <Typography.Paragraph type="secondary">Inherit uses role defaults. Explicit overrides can be revoked at any time.</Typography.Paragraph>
                          <Row gutter={[12, 12]}>
                            {permissionActions.map((action) => (
                              <Col key={action} xs={24} md={12} xl={8}>
                                <Typography.Text style={{ display: 'block' }}>{action}</Typography.Text>
                                <Select style={{ width: '100%' }} value={overrides[action] ?? 'inherit'}
                                  onChange={(scope) => {
                                    setOverrides((prev) => {
                                      const next = { ...prev };
                                      if (scope === 'inherit') delete next[action];
                                      else next[action] = scope as Scope;
                                      return next;
                                    });
                                  }}
                                  options={[
                                    { label: 'Inherit preset', value: 'inherit' },
                                    ...scopes.map((scope) => ({ label: scope, value: scope })),
                                  ]} />
                              </Col>
                            ))}
                          </Row>
                        </Card>
                      )}
                      {selected && (
                        <Card title="Assigned inbounds"
                          extra={<Button loading={saving} onClick={() => void saveAssignments()} type="primary">Save assignments</Button>}>
                          <Select mode="multiple" style={{ width: '100%' }} placeholder="Choose shared inbounds"
                            value={Object.keys(assignments).map(Number)}
                            options={inbounds.map((ib) => ({
                              label: `#${ib.id} · ${ib.remark} · ${ib.protocol}:${ib.port}`, value: ib.id,
                            }))}
                            onChange={(ids) => setAssignments((previous) => {
                              const next: Record<number, boolean> = {};
                              for (const id of ids) next[id] = previous[id] ?? false;
                              return next;
                            })} />
                          <Space orientation="vertical" style={{ marginTop: 16 }}>
                            {Object.entries(assignments).map(([id, canCreate]) => (
                              <Space key={id}>
                                <Typography.Text>Inbound #{id} — can create clients</Typography.Text>
                                <Switch checked={canCreate}
                                  onChange={(value) => setAssignments((prev) => ({ ...prev, [Number(id)]: value }))} />
                              </Space>
                            ))}
                          </Space>
                        </Card>
                      )}
                    </>
                  )}
                  {profileTarget && (
                    <Card title={isOwner ? `Subscription profile for #${profileTarget}` : 'My subscription profile'}
                      extra={<Button type="primary" loading={saving} onClick={() => void saveProfile()}>Save profile</Button>}>
                      <Row gutter={[12, 16]}>
                        {inputField('title', 'Subscription title')}
                        {inputField('supportId', 'Telegram support ID', '@your_support')}
                        {inputField('supportUrl', 'Support URL', 'https://t.me/your_support')}
                        {inputField('subscriptionBaseUrl', 'Subscription base URL (HTTPS)')}
                        {inputField('remarkTemplate', 'Config name pattern', '{{country}} | {{client}}')}
                        {inputField('shareLinkTemplate', 'Share-link template name')}
                        {inputField('pageTemplate', 'Subscription page template name')}
                      </Row>
                    </Card>
                  )}
                  {!isOwner && <AssignedInboundViewer />}
                  {!isOwner && <StaffClientsPanel />}
                </>
              )}
            </Space>
          </Layout.Content>
        </Layout>
      </Layout>
      <Modal open={createVisible} title="Create administrator" footer={null} destroyOnHidden
        onCancel={() => setCreateVisible(false)}>
        <Form form={createForm} layout="vertical" onFinish={(values) => void createUser(values)}
          initialValues={{ role: 'reseller', enabled: false }}>
          <Form.Item name="username" label="Username" rules={[{ required: true }, { min: 3 }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="password" label="Password" rules={[{ required: true }, { min: 12 }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="role" label="Role" rules={[{ required: true }]}>
            <Select options={roles.map((r) => ({ value: r, label: r.toUpperCase() }))} />
          </Form.Item>
          <Form.Item name="enabled" label="Enable account" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Space>
            <Button type="primary" htmlType="submit" loading={saving}>Create</Button>
            <Button onClick={() => setCreateVisible(false)}>Cancel</Button>
          </Space>
        </Form>
      </Modal>
    </ConfigProvider>
  );
}

function AssignedInboundViewer() {
  const [rows, setRows] = useState<InboundOption[]>([]);
  useEffect(() => {
    void HttpUtil.get<InboundOption[]>(`${base}/me/inbounds`, undefined, { silent: true })
      .then((r) => { if (r.success) setRows(r.obj ?? []); });
  }, []);
  return (
    <Card title="My assigned inbounds">
      <Table<InboundOption> size="small" pagination={false} rowKey="id" dataSource={rows}
        columns={[
          { title: 'ID', dataIndex: 'id' },
          { title: 'Name', dataIndex: 'remark' },
          { title: 'Protocol', dataIndex: 'protocol' },
          { title: 'Port', dataIndex: 'port' },
        ]} />
    </Card>
  );
}


type OwnClient = {
  id: number;
  email: string;
  subId: string;
  totalGB: number;
  expiryTime: number;
  enable: boolean;
};
type StaffInbound = InboundOption & { canCreate: boolean };

function StaffClientsPanel() {
  const [members, setMembers] = useState<OwnClient[]>([]);
  const [inbounds, setInbounds] = useState<StaffInbound[]>([]);
  const [selected, setSelected] = useState<number[]>([]);
  const [email, setEmail] = useState('');
  const [quotaGB, setQuotaGB] = useState<number>(50);
  const [durationDays, setDurationDays] = useState<number>(30);
  const [busy, setBusy] = useState(false);
  const [messageApi, holder] = message.useMessage();

  const refresh = useCallback(async () => {
    const response = await HttpUtil.get<OwnClient[]>(`${base}/me/clients`, undefined, { silent: true });
    if (response.success) setMembers(response.obj ?? []);
    else messageApi.error(response.msg || 'Unable to load own clients');
  }, [messageApi]);

  useEffect(() => {
    void refresh();
    void HttpUtil.get<StaffInbound[]>(`${base}/me/inbounds`, undefined, { silent: true })
      .then((r) => { if (r.success) setInbounds(r.obj ?? []); });
  }, [refresh]);

  async function createClient() {
    if (!email.trim() || selected.length === 0 || quotaGB <= 0 || durationDays < 0) {
      messageApi.error('Specify a client, quota, duration and at least one writable inbound');
      return;
    }
    setBusy(true);
    try {
      const expiryTime = durationDays > 0 ? Date.now() + durationDays * 86_400_000 : 0;
      const response = await HttpUtil.post(`${base}/me/clients/create`, {
        client: {
          email: email.trim(),
          totalGB: Math.round(quotaGB * 1_073_741_824),
          expiryTime,
          enable: true,
        },
        inboundIds: selected,
      }, { silent: true });
      if (!response.success) messageApi.error(response.msg || 'Unable to create client');
      else {
        messageApi.success('Client provisioned');
        setEmail('');
        await refresh();
      }
    } finally { setBusy(false); }
  }

  async function deleteClient(clientEmail: string) {
    setBusy(true);
    try {
      const response = await HttpUtil.post(
        `${base}/me/clients/delete/${encodeURIComponent(clientEmail)}`,
        undefined, { silent: true },
      );
      if (!response.success) messageApi.error(response.msg || 'Client delete failed');
      else { messageApi.success('Client deleted'); await refresh(); }
    } finally { setBusy(false); }
  }

  return (
    <Space orientation="vertical" size="large" style={{ width: '100%' }}>
      {holder}
      <Card title="Create a client on assigned inbounds">
        <Row gutter={[12, 12]}>
          <Col xs={24} md={10}>
            <Typography.Text>Client email / identifier</Typography.Text>
            <Input value={email} onChange={(e) => setEmail(e.target.value)}
              placeholder="customer001" maxLength={128} />
          </Col>
          <Col xs={12} md={7}>
            <Typography.Text>Traffic quota (GiB)</Typography.Text>
            <InputNumber min={1} max={100000} value={quotaGB}
              onChange={(value) => setQuotaGB(value ?? 50)} style={{ width: '100%' }} />
          </Col>
          <Col xs={12} md={7}>
            <Typography.Text>Validity (days, 0 = unlimited)</Typography.Text>
            <InputNumber min={0} max={3650} value={durationDays}
              onChange={(value) => setDurationDays(value ?? 30)} style={{ width: '100%' }} />
          </Col>
          <Col span={24}>
            <Typography.Text>Writable inbounds</Typography.Text>
            <Select mode="multiple" style={{ width: '100%' }} value={selected}
              onChange={setSelected}
              options={inbounds.filter((ib) => ib.canCreate).map((ib) => ({
                value: ib.id, label: `#${ib.id} - ${ib.remark} (${ib.protocol})`,
              }))}
              placeholder="Only inbounds assigned for client creation appear here" />
          </Col>
          <Col span={24}>
            <Button type="primary" loading={busy} onClick={() => void createClient()}>
              Create client
            </Button>
          </Col>
        </Row>
      </Card>
      <Card title="My clients">
        <Table<OwnClient> size="small" rowKey="id" dataSource={members}
          pagination={{ pageSize: 20 }}
          scroll={{ x: 650 }}
          columns={[
            { title: 'Client', dataIndex: 'email' },
            { title: 'Quota (GiB)', dataIndex: 'totalGB',
              render: (v: number) => (v / 1_073_741_824).toFixed(1) },
            { title: 'Expiry', dataIndex: 'expiryTime',
              render: (v: number) => v > 0 ? new Date(v).toLocaleDateString() : 'Unlimited' },
            { title: 'Status', dataIndex: 'enable',
              render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? 'Enabled' : 'Disabled'}</Tag> },
            { title: 'Action', render: (_, record) => (
              <Popconfirm title="Delete this client?" description="This removes its VPN credentials from all inbounds."
                onConfirm={() => void deleteClient(record.email)}>
                <Button danger size="small" loading={busy}>Delete</Button>
              </Popconfirm>
            ) },
          ]} />
      </Card>
    </Space>
  );
}
