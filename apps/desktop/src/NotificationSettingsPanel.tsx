import { useEffect, useState } from "react";
import type { AppSettings } from "./generated/AppSettings";
import type { NotificationChannelSecretInput } from "./generated/NotificationChannelSecretInput";
import type { NotificationChannelView } from "./generated/NotificationChannelView";
import type { NotificationPreview } from "./generated/NotificationPreview";
import type { SaveNotificationChannelInput } from "./generated/SaveNotificationChannelInput";
import { api } from "./api";
import type { NoticeSetter, T } from "./WorkspaceContext";
import { safeError } from "./utils";

type Props = {
  settings: AppSettings;
  saveSettings: (settings: AppSettings) => Promise<void>;
  setNotice: NoticeSetter;
  t: T;
};

type ChannelKind = NotificationChannelSecretInput["kind"];

export function NotificationSettingsPanel({ settings, saveSettings, setNotice, t }: Props) {
  const [channels, setChannels] = useState<NotificationChannelView[]>([]);
  const [kind, setKind] = useState<ChannelKind>("webhook");
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState(465);
  const [tls, setTls] = useState<"implicit_tls" | "start_tls">("implicit_tls");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [minPriority, setMinPriority] = useState(70);
  const [enabled, setEnabled] = useState(true);
  const [outboundApproved, setOutboundApproved] = useState(false);
  const [preview, setPreview] = useState<NotificationPreview | null>(null);
  const [busy, setBusy] = useState(false);

  async function refreshChannels() {
    try {
      setChannels(await api.notificationChannels());
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    }
  }

  useEffect(() => {
    void refreshChannels();
    // Load the current persisted channel list once after mounting Settings.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function config(): NotificationChannelSecretInput {
    if (kind === "smtp") {
      return {
        kind,
        host,
        port,
        tls,
        username: username || null,
        password: password || null,
        from,
        to: to
          .split(",")
          .map((address) => address.trim())
          .filter(Boolean),
      };
    }
    if (kind === "ntfy") return { kind, url, token: token || null };
    return { kind, url };
  }

  function input(): SaveNotificationChannelInput {
    return {
      id: null,
      config: config(),
      enabled,
      min_priority: minPriority,
      outbound_approved: outboundApproved,
    };
  }

  async function showPreview() {
    try {
      setPreview(await api.previewNotification(input()));
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    }
  }

  async function saveChannel() {
    setBusy(true);
    try {
      const saved = await api.saveNotificationChannel(input());
      setChannels((current) => [saved, ...current.filter((channel) => channel.id !== saved.id)]);
      setNotice({ kind: "success", message: t("settings.notificationSaved") });
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    } finally {
      setBusy(false);
    }
  }

  async function sendTest(channelId: string) {
    setBusy(true);
    try {
      await api.sendTestNotification(channelId);
      setNotice({ kind: "success", message: t("settings.notificationTestSent") });
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    } finally {
      setBusy(false);
    }
  }

  async function deleteChannel(channelId: string) {
    try {
      await api.deleteNotificationChannel(channelId);
      setChannels((current) => current.filter((channel) => channel.id !== channelId));
      setNotice({ kind: "success", message: t("settings.notificationDeleted") });
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    }
  }

  async function toggleChannel(channel: NotificationChannelView, isEnabled: boolean) {
    try {
      const updated = await api.updateNotificationChannel({
        id: channel.id,
        enabled: isEnabled,
        min_priority: channel.min_priority,
      });
      setChannels((current) => current.map((entry) => (entry.id === updated.id ? updated : entry)));
    } catch (error) {
      setNotice({ kind: "error", message: safeError(error, t) });
    }
  }

  return (
    <section className="panel settings-panel">
      <h2>{t("settings.notifications")}</h2>
      <label className="setting-row">
        <span>
          <strong>{t("settings.desktopNotifications")}</strong>
          <small>{t("settings.desktopNotificationsHelp")}</small>
        </span>
        <input
          type="checkbox"
          checked={settings.desktop_notifications_enabled}
          onChange={(event) =>
            void saveSettings({ ...settings, desktop_notifications_enabled: event.target.checked })
          }
        />
      </label>
      <label className="setting-row">
        <span>
          <strong>{t("settings.outboundNotifications")}</strong>
          <small>{t("settings.outboundNotificationsHelp")}</small>
        </span>
        <input
          type="checkbox"
          checked={settings.outbound_notifications_enabled}
          onChange={(event) =>
            void saveSettings({ ...settings, outbound_notifications_enabled: event.target.checked })
          }
        />
      </label>
      <label className="setting-row">
        <span>
          <strong>{t("settings.dailySummary")}</strong>
          <small>{t("settings.dailySummaryHelp")}</small>
        </span>
        <input
          type="checkbox"
          checked={settings.daily_summary_enabled}
          onChange={(event) =>
            void saveSettings({ ...settings, daily_summary_enabled: event.target.checked })
          }
        />
      </label>

      <h3>{t("settings.notificationChannels")}</h3>
      {channels.length === 0 ? (
        <p>{t("settings.noNotificationChannels")}</p>
      ) : (
        <ul className="notification-channel-list">
          {channels.map((channel) => (
            <li className="notification-channel-card" key={channel.id}>
              <span>
                <strong>{t(`settings.channel.${channel.kind}`)}</strong>
                <small>
                  {channel.approved_destination ?? t("settings.approvalMissing")} ·{" "}
                  {t("settings.priorityAtLeast")} {channel.min_priority}
                </small>
              </span>
              <span className="button-row">
                <label className="channel-enabled-toggle">
                  <span>{t("settings.channelEnabled")}</span>
                  <input
                    type="checkbox"
                    aria-label={`${t("settings.channelEnabled")} ${t(`settings.channel.${channel.kind}`)}`}
                    checked={channel.enabled}
                    onChange={(event) => void toggleChannel(channel, event.target.checked)}
                  />
                </label>
                <button
                  className="button secondary"
                  disabled={
                    busy || (channel.kind !== "desktop" && !settings.outbound_notifications_enabled)
                  }
                  onClick={() => void sendTest(channel.id)}
                >
                  {t("settings.testNotification")}
                </button>
                <button className="button secondary" onClick={() => void deleteChannel(channel.id)}>
                  {t("actions.delete")}
                </button>
              </span>
            </li>
          ))}
        </ul>
      )}

      <div className="notification-channel-form">
        <h3>{t("settings.addNotificationChannel")}</h3>
        <label className="field">
          <span>{t("settings.channelType")}</span>
          <select value={kind} onChange={(event) => setKind(event.target.value as ChannelKind)}>
            {(["webhook", "slack", "discord", "ntfy", "smtp"] as const).map((channelKind) => (
              <option value={channelKind} key={channelKind}>
                {t(`settings.channel.${channelKind}`)}
              </option>
            ))}
          </select>
        </label>
        {kind === "smtp" ? (
          <div className="form-grid">
            <label className="field">
              <span>{t("settings.smtpHost")}</span>
              <input value={host} onChange={(event) => setHost(event.target.value)} />
            </label>
            <label className="field">
              <span>{t("settings.smtpPort")}</span>
              <input
                type="number"
                min={1}
                max={65535}
                value={port}
                onChange={(event) => setPort(Number(event.target.value))}
              />
            </label>
            <label className="field">
              <span>{t("settings.smtpTls")}</span>
              <select value={tls} onChange={(event) => setTls(event.target.value as typeof tls)}>
                <option value="implicit_tls">{t("settings.implicitTls")}</option>
                <option value="start_tls">{t("settings.startTls")}</option>
              </select>
            </label>
            <label className="field">
              <span>{t("settings.smtpUsername")}</span>
              <input
                autoComplete="off"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
              />
            </label>
            <label className="field">
              <span>{t("settings.smtpPassword")}</span>
              <input
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>
            <label className="field">
              <span>{t("settings.smtpFrom")}</span>
              <input type="email" value={from} onChange={(event) => setFrom(event.target.value)} />
            </label>
            <label className="field">
              <span>{t("settings.smtpTo")}</span>
              <input value={to} onChange={(event) => setTo(event.target.value)} />
            </label>
          </div>
        ) : (
          <div className="form-grid">
            <label className="field">
              <span>{t("settings.channelUrl")}</span>
              <input
                type="url"
                autoComplete="off"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
              />
            </label>
            {kind === "ntfy" && (
              <label className="field">
                <span>{t("settings.ntfyToken")}</span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={token}
                  onChange={(event) => setToken(event.target.value)}
                />
              </label>
            )}
          </div>
        )}
        <div className="form-grid">
          <label className="field">
            <span>{t("settings.minimumPriority")}</span>
            <input
              type="number"
              min={0}
              max={100}
              value={minPriority}
              onChange={(event) => setMinPriority(Number(event.target.value))}
            />
          </label>
          <label className="setting-row compact-setting">
            <span>{t("settings.channelEnabled")}</span>
            <input
              type="checkbox"
              checked={enabled}
              onChange={(event) => setEnabled(event.target.checked)}
            />
          </label>
        </div>
        <label className="setting-row">
          <span>
            <strong>{t("settings.approveDestination")}</strong>
            <small>{t("settings.approveDestinationHelp")}</small>
          </span>
          <input
            type="checkbox"
            checked={outboundApproved}
            onChange={(event) => setOutboundApproved(event.target.checked)}
          />
        </label>
        <div className="button-row">
          <button className="button secondary" onClick={() => void showPreview()}>
            {t("settings.previewNotification")}
          </button>
          <button className="button primary" disabled={busy} onClick={() => void saveChannel()}>
            {t("actions.save")}
          </button>
        </div>
        {preview && (
          <div className="notification-preview" aria-live="polite">
            <strong>{preview.title}</strong>
            <p>{preview.message}</p>
            {preview.destination && <small>{preview.destination}</small>}
          </div>
        )}
      </div>
    </section>
  );
}
