import { useState } from "react";
import type { Finding } from "../generated/Finding";
import type { FindingDispositionReason } from "../generated/FindingDispositionReason";
import type { FindingStatus } from "../generated/FindingStatus";
import type { WorkspaceData } from "../api";
import type { T } from "../WorkspaceContext";

const dispositionStatuses: FindingStatus[] = ["not_reachable", "accepted_risk", "false_positive"];
export function StatusDialog({
  finding,
  instance,
  t,
  close,
  onSave,
}: {
  finding: Finding;
  instance: WorkspaceData["instances"][number] | undefined;
  t: T;
  close: () => void;
  onSave: (change: {
    finding_id: string;
    status: FindingStatus;
    reason: FindingDispositionReason;
    scope: string;
    scope_id: string;
    expires_at: string | null;
  }) => Promise<void>;
}) {
  const [status, setStatus] = useState<FindingStatus>("not_reachable");
  const [reason, setReason] = useState<FindingDispositionReason>("no_affected_code_path");
  const [scope, setScope] = useState("finding");
  const [expires, setExpires] = useState("");
  const allowedReasons =
    status === "accepted_risk"
      ? ([
          "business_accepted",
          "compensating_control",
          "temporary_exception",
          "fix_planned",
        ] as FindingDispositionReason[])
      : status === "false_positive"
        ? ([
            "duplicate_finding",
            "incorrect_package",
            "unaffected_version",
            "no_affected_code_path",
            "other_reviewed",
          ] as FindingDispositionReason[])
        : ([
            "no_affected_code_path",
            "configuration_prevents_reachability",
            "other_reviewed",
          ] as FindingDispositionReason[]);
  const scopes = [
    { value: "finding", id: finding.id },
    ...(instance?.project_id ? [{ value: "project", id: instance.project_id }] : []),
    ...(instance?.asset_id ? [{ value: "asset", id: instance.asset_id }] : []),
    ...(instance?.deployment_id ? [{ value: "deployment", id: instance.deployment_id }] : []),
  ];
  const scopeId = scopes.find((item) => item.value === scope)?.id ?? finding.id;
  return (
    <div
      className="dialog-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) close();
      }}
    >
      <section
        className="dialog panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="status-dialog-title"
      >
        <div className="panel-heading">
          <h2 id="status-dialog-title">{t("findings.changeTitle")}</h2>
          <button className="icon-button" aria-label={t("actions.close")} onClick={close}>
            ×
          </button>
        </div>
        <p>{t("findings.statusHelp")}</p>
        <label className="field">
          <span>{t("findings.newStatus")}</span>
          <select
            value={status}
            onChange={(event) => {
              const next = event.target.value as FindingStatus;
              setStatus(next);
              setReason(next === "accepted_risk" ? "business_accepted" : "no_affected_code_path");
            }}
          >
            {dispositionStatuses.map((value) => (
              <option key={value} value={value}>
                {t(`status.${value}`)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>{t("findings.dispositionReason")}</span>
          <select
            value={reason}
            onChange={(event) => setReason(event.target.value as FindingDispositionReason)}
          >
            {allowedReasons.map((value) => (
              <option key={value} value={value}>
                {t(`reason.${value}`)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>{t("findings.scope")}</span>
          <select value={scope} onChange={(event) => setScope(event.target.value)}>
            {scopes.map((item) => (
              <option value={item.value} key={item.value}>
                {t(`scope.${item.value}`)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>{t("findings.expiry")}</span>
          <input
            type="date"
            value={expires}
            onChange={(event) => setExpires(event.target.value)}
            required={status === "accepted_risk" || status === "false_positive"}
          />
        </label>
        <div className="button-row end">
          <button className="button quiet" onClick={close}>
            {t("actions.cancel")}
          </button>
          <button
            className="button primary"
            disabled={(status === "accepted_risk" || status === "false_positive") && !expires}
            onClick={() =>
              void onSave({
                finding_id: finding.id,
                status,
                reason,
                scope,
                scope_id: scopeId,
                expires_at: expires ? new Date(`${expires}T23:59:59Z`).toISOString() : null,
              })
            }
          >
            {t("actions.save")}
          </button>
        </div>
      </section>
    </div>
  );
}
