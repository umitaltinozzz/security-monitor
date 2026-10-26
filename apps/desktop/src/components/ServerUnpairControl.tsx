import { useState } from "react";
import type { Asset } from "../generated/Asset";
import type { T } from "../WorkspaceContext";

export function ServerUnpairControl({
  asset,
  t,
  onConfirm,
}: {
  asset: Asset;
  t: T;
  onConfirm: (deleteHistory: boolean) => Promise<boolean>;
}) {
  const [open, setOpen] = useState(false);
  const [deleteHistory, setDeleteHistory] = useState(false);
  const [pending, setPending] = useState(false);

  async function confirm() {
    setPending(true);
    try {
      if (await onConfirm(deleteHistory)) setOpen(false);
    } finally {
      setPending(false);
    }
  }

  function openConfirmation() {
    setDeleteHistory(false);
    setOpen(true);
  }

  return (
    <>
      <button className="button secondary" onClick={openConfirmation}>
        {t("servers.unpair")}
      </button>
      {open && (
        <div
          className="approval-box"
          role="dialog"
          aria-modal="true"
          aria-labelledby={`unpair-title-${asset.id}`}
        >
          <h3 id={`unpair-title-${asset.id}`}>{t("servers.unpairTitle")}</h3>
          <p>{t("servers.unpairAuthorizedKeysWarning")}</p>
          <fieldset className="form-panel">
            <legend>{t("servers.historyChoice")}</legend>
            <label className="check-field">
              <input
                type="radio"
                name={`history-${asset.id}`}
                checked={!deleteHistory}
                onChange={() => setDeleteHistory(false)}
              />
              {t("servers.keepHistory")}
            </label>
            <label className="check-field">
              <input
                type="radio"
                name={`history-${asset.id}`}
                checked={deleteHistory}
                onChange={() => setDeleteHistory(true)}
              />
              {t("servers.deleteHistory")}
            </label>
          </fieldset>
          <div className="button-row">
            <button className="button primary" disabled={pending} onClick={() => void confirm()}>
              {t("servers.confirmUnpair")}
            </button>
            <button
              className="button quiet"
              disabled={pending}
              onClick={() => {
                setDeleteHistory(false);
                setOpen(false);
              }}
            >
              {t("actions.cancel")}
            </button>
          </div>
        </div>
      )}
    </>
  );
}
