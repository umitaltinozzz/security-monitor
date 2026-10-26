import { useState } from "react";
import type { ScannerFinding } from "../generated/ScannerFinding";
import type { ScannerFindingStatus } from "../generated/ScannerFindingStatus";
import type { T } from "../WorkspaceContext";

const statuses: ScannerFindingStatus[] = [
  "needs_review",
  "confirmed",
  "accepted_risk",
  "false_positive",
  "resolved",
];

export function ScannerFindingReviewDialog({
  finding,
  t,
  close,
  onSave,
}: {
  finding: ScannerFinding;
  t: T;
  close: () => void;
  onSave: (change: {
    finding_id: string;
    status: ScannerFindingStatus;
    reason: string | null;
  }) => Promise<void>;
}) {
  const [status, setStatus] = useState<ScannerFindingStatus>(finding.status);
  const [reason, setReason] = useState(finding.review_reason ?? "");
  const reasonRequired = status !== "needs_review";
  const trimmedReason = reason.trim();
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
        aria-labelledby="scanner-review-title"
      >
        <div className="panel-heading">
          <h2 id="scanner-review-title">{t("findings.scannerReviewTitle")}</h2>
          <button className="icon-button" aria-label={t("actions.close")} onClick={close}>
            ×
          </button>
        </div>
        <p>{finding.title ?? finding.rule_id ?? finding.scanner}</p>
        <label className="field">
          <span>{t("findings.scannerReviewStatus")}</span>
          <select
            value={status}
            onChange={(event) => setStatus(event.target.value as ScannerFindingStatus)}
          >
            {statuses.map((value) => (
              <option key={value} value={value}>
                {t(`findings.scannerStatus.${value}`)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>{t("findings.scannerReviewReason")}</span>
          <textarea
            value={reason}
            maxLength={1000}
            required={reasonRequired}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
        <p>{t("findings.scannerReviewHelp")}</p>
        <div className="button-row end">
          <button className="button quiet" onClick={close}>
            {t("actions.cancel")}
          </button>
          <button
            className="button primary"
            disabled={reasonRequired && trimmedReason.length === 0}
            onClick={() =>
              void onSave({
                finding_id: finding.id,
                status,
                reason: reasonRequired ? trimmedReason : null,
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
