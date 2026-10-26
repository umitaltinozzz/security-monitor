import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Asset } from "../generated/Asset";
import { translate } from "../test-fixtures";
import { ServerUnpairControl } from "./ServerUnpairControl";

const asset: Asset = {
  id: "server-1",
  asset_type: "server",
  hostname_alias: "production",
  environment: "production",
  ssh_target_ref: "secmon-keyring:v1:00000000-0000-4000-8000-000000000001",
  host_key_fingerprint: "SHA256:fixture",
  last_seen_at: null,
  last_success_at: null,
  removed_at: null,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

describe("ServerUnpairControl", () => {
  it("opens confirmation, defaults to keeping history, and submits the selected choice", async () => {
    const onConfirm = vi.fn(async () => true);
    render(<ServerUnpairControl asset={asset} t={translate} onConfirm={onConfirm} />);

    fireEvent.click(screen.getByRole("button", { name: "servers.unpair" }));

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("servers.unpairAuthorizedKeysWarning")).toBeInTheDocument();
    expect(screen.getByLabelText("servers.keepHistory")).toBeChecked();
    expect(screen.getByLabelText("servers.deleteHistory")).not.toBeChecked();

    fireEvent.click(screen.getByLabelText("servers.deleteHistory"));
    fireEvent.click(screen.getByRole("button", { name: "servers.confirmUnpair" }));

    await waitFor(() => expect(onConfirm).toHaveBeenCalledWith(true));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });
});
