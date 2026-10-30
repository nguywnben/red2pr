import {
  Red2PrApiError,
  type NotificationChannel,
  type NotificationDestinationCreateRequest,
  type NotificationInboxItem,
  type NotificationPreferencesPatchRequest,
  type MeResponse,
  type Workspace,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useMemo, useState } from "react";
import { Link } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { Button, StateView } from "../../shared/ui";
import { formatUtcTimestamp } from "../auth";
import { generateClientUuidV7 } from "../queues";

const CHANNELS: readonly NotificationChannel[] = ["email", "telegram", "slack", "discord", "webhook"];
const SEVERITIES = ["info", "success", "warning", "action", "error", "high", "critical"] as const;
const EVENT_TYPES: readonly NotificationInboxItem["event_type"][] = [
  "provider.connection.created", "provider.run.failed", "provider.run.retried",
  "repair.session.created", "repair.diagnosed", "repair.reproduction.completed",
  "repair.patch.proposed", "repair.verification.completed", "repair.approval.requested",
  "repair.approval.decided", "repair.publication.created", "repair.remote_ci.completed",
  "repair.blocked", "repair.cancelled", "worker.offline", "worker.quarantined",
  "integration.disconnected", "usage.budget.exceeded", "security.policy.denied",
  "backup.failed", "release.update_available", "identity.permission_revoked",
  "notification.delivery.failed", "operations.restore.completed",
];

export interface NotificationsPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

export function NotificationsPage({ workspace, me }: NotificationsPageProps): React.JSX.Element {
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const ws = workspace.slug ?? workspace.id;
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [cursor, setCursor] = useState<string | null>(null);
  const [cursorHistory, setCursorHistory] = useState<readonly (string | null)[]>([]);
  const [channel, setChannel] = useState<NotificationChannel>("email");
  const [scope, setScope] = useState<"user" | "workspace">("workspace");
  const [address, setAddress] = useState("");
  const [consentId, setConsentId] = useState("");
  const [secretRef, setSecretRef] = useState("");
  const [credentialValues, setCredentialValues] = useState<Record<string, string>>({});
  const [oneTimeWebhookKey, setOneTimeWebhookKey] = useState<{ readonly destinationId: string; readonly keyId: string; readonly secret: string } | null>(null);
  const [replacementAddress, setReplacementAddress] = useState("");
  const [replacementConsentId, setReplacementConsentId] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  const inboxQuery = useQuery({
    queryKey: ["workspace", ws, "notifications", unreadOnly, cursor],
    queryFn: () => api.listWorkspaceNotifications(ws, { unread: unreadOnly || undefined, limit: 50, ...(cursor ? { cursor } : {}) }),
  });
  const destinationsQuery = useQuery({
    queryKey: ["workspace", ws, "notification-destinations"],
    queryFn: () => api.listNotificationDestinations(ws, { limit: 50 }),
  });
  const deliveriesQuery = useQuery({
    queryKey: ["workspace", ws, "notification-deliveries"],
    queryFn: () => api.listNotificationDeliveries(ws, { limit: 50 }),
  });
  const preferencesQuery = useQuery({
    queryKey: ["workspace", ws, "notification-preferences"],
    queryFn: () => api.getNotificationPreferences(workspace.id),
  });

  const refresh = async (): Promise<void> => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["workspace", ws, "notifications"] }),
      queryClient.invalidateQueries({ queryKey: ["workspace", ws, "notification-destinations"] }),
      queryClient.invalidateQueries({ queryKey: ["workspace", ws, "notification-deliveries"] }),
      queryClient.invalidateQueries({ queryKey: ["workspace", ws, "notification-preferences"] }),
    ]);
  };

  const readMutation = useMutation({
    mutationFn: (item: NotificationInboxItem) =>
      api.updateWorkspaceNotificationReadState(ws, item.id, { read: item.read_at == null }),
    onSuccess: async () => { setNotice("Inbox state updated."); await refresh(); },
    onError: (error: unknown) => setNotice(safeError(error, "Could not update the inbox item.")),
  });
  const preferenceMutation = useMutation({
    mutationFn: (body: NotificationPreferencesPatchRequest) => api.patchNotificationPreferences(body),
    onSuccess: async () => { setNotice("Notification preferences saved."); await refresh(); },
    onError: (error: unknown) => setNotice(safeError(error, "Could not save notification preferences.")),
  });
  const destinationMutation = useMutation({
    mutationFn: (body: NotificationDestinationCreateRequest) =>
      api.createNotificationDestination(ws, body, { idempotencyKey: generateClientUuidV7() }),
    onSuccess: async () => { setAddress(""); setConsentId(""); setSecretRef(""); setNotice("Destination saved. Configure its encrypted credential and complete a confirmed test before delivery."); await refresh(); },
    onError: (error: unknown) => setNotice(safeError(error, "Could not save destination.")),
  });
  const testMutation = useMutation({
    mutationFn: (id: string) => api.testNotificationDestination(ws, id, { confirmed: true }),
    onSuccess: () => setNotice("Test request accepted."),
    onError: (error: unknown) => setNotice(safeError(error, "No test message was sent.")),
  });
  const credentialMutation = useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) =>
      api.updateNotificationCredential(ws, id, { secret_value: value }),
    onSuccess: async (_result, variables) => {
      setCredentialValues((values) => ({ ...values, [variables.id]: "" }));
      setNotice("Encrypted credentials saved. Run a confirmed test to enable delivery.");
      await refresh();
    },
    onError: (error: unknown) => setNotice(safeError(error, "Could not store notification credentials.")),
  });
  const webhookKeyMutation = useMutation({
    mutationFn: (id: string) => api.rotateWebhookSigningKey(ws, id),
    onSuccess: async (result, destinationId) => {
      setOneTimeWebhookKey({ destinationId, keyId: result.data.key_id, secret: result.data.secret });
      setNotice("New signing key issued. Copy it now; Red2PR will not show it again.");
      await refresh();
    },
    onError: (error: unknown) => setNotice(safeError(error, "Could not rotate the webhook signing key.")),
  });
  const patchMutation = useMutation({
    mutationFn: ({ id, version, address: nextAddress, consent }: { id: string; version: number; address: string; consent: string }) =>
      api.patchNotificationDestination(ws, id, { address: nextAddress, consent_id: consent }, { ifMatch: `"v${version}"` }),
    onSuccess: async () => { setReplacementAddress(""); setReplacementConsentId(""); setNotice("Destination updated; it requires re-verification before delivery."); await refresh(); },
    onError: (error: unknown) => setNotice(safeError(error, "Could not update destination.")),
  });
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteNotificationDestination(ws, id),
    onSuccess: async () => { setNotice("Destination removed; delivery history is retained."); await refresh(); },
    onError: (error: unknown) => setNotice(safeError(error, "Could not remove destination.")),
  });

  const items = useMemo(() => inboxQuery.data?.data.items ?? [], [inboxQuery.data]);
  const destinations = destinationsQuery.data?.data.items ?? [];
  const deliveries = deliveriesQuery.data?.data.items ?? [];
  const canManage = (me.memberships ?? []).some((membership) =>
    membership.workspace_id === workspace.id && ["admin", "maintainer"].includes(membership.role),
  );
  const pending = readMutation.isPending || preferenceMutation.isPending || destinationMutation.isPending || testMutation.isPending || credentialMutation.isPending || webhookKeyMutation.isPending || patchMutation.isPending || deleteMutation.isPending;

  return <main className="red2pr-page-stack" data-testid="notifications-page">
    <header className="red2pr-page-header"><div><h1>Notifications</h1><p>Review workspace events, configure delivery preferences, and inspect delivery receipts.</p></div></header>
    {notice ? <div className="red2pr-inline-alert" role="status" aria-live="polite">{notice}</div> : null}
    {oneTimeWebhookKey ? <section className="red2pr-surface red2pr-card-section" aria-label="One-time webhook signing key" role="alert"><h2>Copy the new webhook signing key</h2><p>Key ID: <code>{oneTimeWebhookKey.keyId}</code>. This secret is shown once. The previous key remains valid for 48 hours.</p><label htmlFor="one-time-webhook-secret" className="red2pr-field-label">Signing secret</label><input id="one-time-webhook-secret" className="red2pr-control-input" readOnly value={oneTimeWebhookKey.secret} autoComplete="off" /><Button label="I copied the key" variant="secondary" onClick={() => setOneTimeWebhookKey(null)} /></section> : null}

    <section className="red2pr-surface red2pr-card-section" aria-labelledby="inbox-heading">
      <header className="red2pr-card-header"><div><h2 id="inbox-heading">Inbox</h2><p>Security and audit notices remain in the inbox regardless of delivery preferences.</p></div>
        <label className="red2pr-field-label"><input type="checkbox" checked={unreadOnly} onChange={(event) => { setUnreadOnly(event.target.checked); setCursor(null); setCursorHistory([]); }} /> Unread only</label>
      </header>
      {inboxQuery.isPending ? <StateView state="loading" /> : inboxQuery.isError ? <StateView state={inboxQuery.error instanceof Red2PrApiError && inboxQuery.error.status === 403 ? "forbidden" : "error"} title="Inbox unavailable" description={safeError(inboxQuery.error, "Notification events could not be loaded.")} primaryAction={{ label: "Retry", onClick: () => void inboxQuery.refetch() }} /> : items.length === 0 ? <StateView state="empty" title={unreadOnly ? "No unread notifications" : "No notifications yet"} description="New workspace events will appear here after they are committed to the outbox." /> : <ul className="red2pr-page-stack" aria-label="Notification inbox">{items.map((item) => <li key={item.id} className="red2pr-surface red2pr-card-section" data-testid={`notification-${item.id}`}>
        <div className="red2pr-card-header"><div><h3>{item.title}</h3><p><time dateTime={item.created_at}>{formatUtcTimestamp(item.created_at)}</time> · {item.severity} · {item.event_type}</p></div><span className={`red2pr-badge-pill ${item.is_security ? "red2pr-tone-danger" : item.read_at ? "" : "red2pr-tone-warning"}`}>{item.is_security ? "Security" : item.read_at ? "Read" : "Unread"}</span></div>
        <p>{item.body}</p>
        <div className="red2pr-button-row">{item.deep_link?.startsWith(`/w/${encodeURIComponent(ws)}/`) ? <Link to={item.deep_link}>Open related item</Link> : null}<Button label={item.read_at ? "Mark unread" : "Mark read"} variant="secondary" isDisabled={pending} onClick={() => readMutation.mutate(item)} /></div>
      </li>)}</ul>}
      {items.length > 0 ? <nav className="red2pr-button-row" aria-label="Notification pages"><Button label="Previous page" variant="secondary" isDisabled={cursorHistory.length === 0} onClick={() => { setCursor(cursorHistory.at(-1) ?? null); setCursorHistory((history) => history.slice(0, -1)); }} /><Button label="Next page" variant="secondary" isDisabled={!inboxQuery.data?.data.next_cursor} onClick={() => { const next = inboxQuery.data?.data.next_cursor; if (next) { setCursorHistory((history) => [...history, cursor]); setCursor(next); } }} /></nav> : null}
    </section>

    <section className="red2pr-surface red2pr-card-section" aria-labelledby="preferences-heading">
      <header><h2 id="preferences-heading">Delivery preferences</h2><p>These settings apply to external delivery. They never hide security or audit items from this inbox.</p></header>
      {preferencesQuery.isPending ? <StateView state="loading" /> : preferencesQuery.isError ? <StateView state="error" title="Preferences unavailable" description={safeError(preferencesQuery.error, "Preferences could not be loaded.")} primaryAction={{ label: "Retry", onClick: () => void preferencesQuery.refetch() }} /> : <form className="red2pr-form-stack" onSubmit={(event) => { event.preventDefault(); const data = new FormData(event.currentTarget); const timezoneValue = String(data.get("timezone") ?? "UTC").trim(); const quietEnabled = data.get("quiet_enabled") === "on"; preferenceMutation.mutate({ workspace_id: workspace.id, event_types: data.getAll("event_types").map(String) as NotificationInboxItem["event_type"][], min_severity: String(data.get("min_severity")) as (typeof SEVERITIES)[number], timezone: timezoneValue, quiet_hours: quietEnabled ? { start_hhmm: String(data.get("quiet_start")), end_hhmm: String(data.get("quiet_end")) } : null }); }}>
        <div className="red2pr-field"><label htmlFor="notification-event-types" className="red2pr-field-label">Subscribed event types</label><select id="notification-event-types" name="event_types" className="red2pr-control-input" multiple defaultValue={preferencesQuery.data.data.event_types}>{EVENT_TYPES.map((eventType) => <option key={eventType} value={eventType}>{eventType}</option>)}</select><p className="red2pr-field-hint">Leave all event types unselected to receive every event on enabled external destinations.</p></div>
        <div className="red2pr-field"><label htmlFor="notification-min-severity" className="red2pr-field-label">Minimum severity</label><select id="notification-min-severity" name="min_severity" className="red2pr-control-input" defaultValue={preferencesQuery.data.data.min_severity}>{SEVERITIES.map((severity) => <option key={severity}>{severity}</option>)}</select></div>
        <div className="red2pr-field"><label htmlFor="notification-timezone" className="red2pr-field-label">IANA timezone</label><input id="notification-timezone" name="timezone" className="red2pr-control-input" defaultValue={preferencesQuery.data.data.timezone} maxLength={80} required /></div>
        <label className="red2pr-field-label"><input type="checkbox" name="quiet_enabled" defaultChecked={Boolean(preferencesQuery.data.data.quiet_hours)} /> Quiet hours</label>
        <div className="red2pr-button-row"><div className="red2pr-field"><label htmlFor="quiet-start" className="red2pr-field-label">Quiet start</label><input id="quiet-start" name="quiet_start" className="red2pr-control-input" type="time" defaultValue={preferencesQuery.data.data.quiet_hours?.start_hhmm ?? "22:00"} /></div><div className="red2pr-field"><label htmlFor="quiet-end" className="red2pr-field-label">Quiet end</label><input id="quiet-end" name="quiet_end" className="red2pr-control-input" type="time" defaultValue={preferencesQuery.data.data.quiet_hours?.end_hhmm ?? "07:00"} /></div></div>
        <Button label="Save preferences" variant="primary" type="submit" isLoading={preferenceMutation.isPending} isDisabled={pending} />
      </form>}
    </section>

    <section className="red2pr-surface red2pr-card-section" aria-labelledby="destinations-heading">
      <header><h2 id="destinations-heading">Delivery destinations</h2><p>Credentials stay encrypted and are never returned. A destination remains disabled for delivery until its confirmed test succeeds.</p></header>
      {destinationsQuery.isPending ? <StateView state="loading" /> : destinationsQuery.isError ? <StateView state="error" title="Destinations unavailable" description={safeError(destinationsQuery.error, "Destinations could not be loaded.")} primaryAction={{ label: "Retry", onClick: () => void destinationsQuery.refetch() }} /> : destinations.length === 0 ? <p>No external destinations are configured.</p> : <ul className="red2pr-page-stack">{destinations.map((destination) => <li key={destination.id} className="red2pr-card-section"><div className="red2pr-card-header"><div><h3>{destination.channel} · {destination.scope}</h3><p>Status: {destination.status}. Secret: {destination.secret_presence.configured ? "configured (value hidden)" : "not configured"}.</p></div><span className="red2pr-badge-pill">{destination.status}</span></div><p>Address is stored by the server and is not returned to the browser.</p>{canManage && ["email", "slack", "discord"].includes(destination.channel) ? <form className="red2pr-form-stack" onSubmit={(event) => { event.preventDefault(); const value = credentialValues[destination.id]?.trim() ?? ""; if (value) credentialMutation.mutate({ id: destination.id, value }); }}><div className="red2pr-field"><label htmlFor={`destination-credential-${destination.id}`} className="red2pr-field-label">Encrypted {destination.channel} credential/configuration</label><textarea id={`destination-credential-${destination.id}`} className="red2pr-control-input" value={credentialValues[destination.id] ?? ""} maxLength={8192} autoComplete="off" onChange={(event) => setCredentialValues((values) => ({ ...values, [destination.id]: event.target.value }))} required /><p className="red2pr-field-hint">{destination.channel === "email" ? "Enter SMTP JSON: host, port 587 with STARTTLS or 465 with TLS, sender, and optional paired username/password." : "Enter the HTTPS incoming webhook URL. The value is write-only and encrypted."}</p></div><Button label="Save encrypted credential" variant="secondary" type="submit" isDisabled={pending || !(credentialValues[destination.id]?.trim())} /></form> : null}{canManage && destination.channel === "webhook" ? <Button label="Rotate signing key" variant="secondary" isDisabled={pending} onClick={() => webhookKeyMutation.mutate(destination.id)} /> : null}{canManage ? <form className="red2pr-form-stack" onSubmit={(event) => { event.preventDefault(); const next = replacementAddress.trim(); const consent = replacementConsentId.trim(); if (next && consent) patchMutation.mutate({ id: destination.id, version: destination.version, address: next, consent }); }}><div className="red2pr-field"><label htmlFor={`destination-address-${destination.id}`} className="red2pr-field-label">Replace address</label><input id={`destination-address-${destination.id}`} className="red2pr-control-input" value={replacementAddress} maxLength={500} onChange={(event) => setReplacementAddress(event.target.value)} required /></div><div className="red2pr-field"><label htmlFor={`destination-consent-${destination.id}`} className="red2pr-field-label">Matching consent ID</label><input id={`destination-consent-${destination.id}`} className="red2pr-control-input" value={replacementConsentId} maxLength={36} onChange={(event) => setReplacementConsentId(event.target.value)} required /></div><Button label="Update address" variant="secondary" type="submit" isDisabled={pending || replacementAddress.trim().length === 0 || replacementConsentId.trim().length === 0} /></form> : null}<div className="red2pr-button-row"><Button label="Preview test send" variant="secondary" isDisabled={!canManage || pending || destination.status !== "ready"} onClick={() => testMutation.mutate(destination.id)} /><Button label="Remove destination" variant="secondary" isDisabled={!canManage || pending} onClick={() => deleteMutation.mutate(destination.id)} /></div></li>)}</ul>}
      {canManage ? <form className="red2pr-form-stack" onSubmit={(event) => { event.preventDefault(); destinationMutation.mutate({ channel, scope, address: address.trim(), consent_id: consentId.trim(), secret_ref: secretRef.trim() || null }); }}>
        <h3>Add a destination</h3><div className="red2pr-field"><label htmlFor="notification-channel" className="red2pr-field-label">Channel</label><select id="notification-channel" className="red2pr-control-input" value={channel} onChange={(event) => setChannel(event.target.value as NotificationChannel)}>{CHANNELS.map((item) => <option key={item} value={item}>{item}</option>)}</select></div>
        <div className="red2pr-field"><label htmlFor="notification-scope" className="red2pr-field-label">Scope</label><select id="notification-scope" className="red2pr-control-input" value={scope} onChange={(event) => setScope(event.target.value as typeof scope)}><option value="workspace">Workspace</option><option value="user">Personal</option></select></div>
        <div className="red2pr-field"><label htmlFor="notification-address" className="red2pr-field-label">Destination address</label><input id="notification-address" className="red2pr-control-input" value={address} maxLength={500} onChange={(event) => setAddress(event.target.value)} required /></div>
        <div className="red2pr-field"><label htmlFor="notification-consent" className="red2pr-field-label">Active notification consent ID</label><input id="notification-consent" className="red2pr-control-input" value={consentId} maxLength={36} onChange={(event) => setConsentId(event.target.value)} required /></div>
        <div className="red2pr-field"><label htmlFor="notification-secret-ref" className="red2pr-field-label">Existing notification-channel secret reference (optional)</label><input id="notification-secret-ref" className="red2pr-control-input" value={secretRef} maxLength={128} onChange={(event) => setSecretRef(event.target.value)} /><p className="red2pr-field-hint">Enter a secret reference from the protected secret store. Never paste a secret value here.</p></div>
        <p className="red2pr-field-hint">The consent must match this address and workspace. The destination starts not configured until credentials and a confirmed verification test are complete.</p>
        <Button label="Save destination" variant="primary" type="submit" isLoading={destinationMutation.isPending} isDisabled={pending || address.trim().length === 0 || consentId.trim().length === 0} />
      </form> : <p role="note">Your workspace role can view destinations but cannot change them.</p>}
    </section>

    <section className="red2pr-surface red2pr-card-section" aria-labelledby="deliveries-heading">
      <header><h2 id="deliveries-heading">Delivery history</h2><p>Accepted means accepted by a transport. An unknown result may have reached a recipient, so Red2PR does not claim it failed or succeeded.</p></header>
      {deliveriesQuery.isPending ? <StateView state="loading" /> : deliveriesQuery.isError ? <StateView state="error" title="Delivery history unavailable" description={safeError(deliveriesQuery.error, "Delivery records could not be loaded.")} primaryAction={{ label: "Retry", onClick: () => void deliveriesQuery.refetch() }} /> : deliveries.length === 0 ? <StateView state="empty" title="No delivery attempts" description="Delivery receipts will appear here when a configured channel adapter processes an event." /> : <div className="red2pr-page-stack">{deliveries.map((delivery) => <article key={delivery.id} className="red2pr-card-section"><h3>{delivery.state}{delivery.possible_duplicate ? " · possible duplicate" : ""}</h3><p>Attempt {delivery.attempt} · <time dateTime={delivery.updated_at}>{formatUtcTimestamp(delivery.updated_at)}</time></p>{delivery.last_error_code ? <p role="note">Last error: {delivery.last_error_code}</p> : null}</article>)}</div>}
    </section>
  </main>;
}

function safeError(error: unknown, fallback: string): string {
  if (error instanceof Red2PrApiError) return `${error.problem.detail} (${error.problem.correlation_id})`;
  if (error instanceof Error) return error.message;
  return fallback;
}
