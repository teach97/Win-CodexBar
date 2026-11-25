import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const tauriMocks = vi.hoisted(() => ({
  getAntigravityOAuthStatus: vi.fn(),
  antigravityOAuthLogin: vi.fn(),
  antigravityOAuthCancelLogin: vi.fn(),
  antigravityOAuthLogout: vi.fn(),
  openPath: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

vi.mock("../../../../../lib/tauri", () => tauriMocks);

import { AntigravityCreds } from "./AntigravityCreds";

const t = (key: string) => key;

describe("AntigravityCreds", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders sign-in action when signed out and client is available", async () => {
    tauriMocks.getAntigravityOAuthStatus.mockResolvedValue({
      signedIn: false,
      email: null,
      credentialsPath: "C:/Users/me/.codexbar/antigravity/oauth_creds.json",
      clientAvailable: true,
      missingClientMessage: null,
    });
    render(<AntigravityCreds t={t} />);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "CredsAntigravitySignInButton" })).toBeEnabled(),
    );
    expect(screen.getByText("CredsStatusNotSignedIn")).toBeTruthy();
  });

  it("completes browser sign-in and shows authenticated email + sign-out action", async () => {
    tauriMocks.getAntigravityOAuthStatus.mockResolvedValue({
      signedIn: false,
      email: null,
      credentialsPath: "C:/Users/me/.codexbar/antigravity/oauth_creds.json",
      clientAvailable: true,
      missingClientMessage: null,
    });
    tauriMocks.antigravityOAuthLogin.mockResolvedValue({
      signedIn: true,
      email: "user@example.com",
      credentialsPath: "C:/Users/me/.codexbar/antigravity/oauth_creds.json",
      clientAvailable: true,
      missingClientMessage: null,
    });

    render(<AntigravityCreds t={t} />);
    const btn = await screen.findByRole("button", { name: "CredsAntigravitySignInButton" });
    await act(async () => {
      fireEvent.click(btn);
    });

    await waitFor(() =>
      expect(screen.getByText("CredsStatusAuthenticated (user@example.com)")).toBeTruthy(),
    );
    expect(screen.getByText("CredsAntigravitySignedInNotice")).toBeTruthy();
    expect(screen.getByRole("button", { name: "CredsAntigravitySignOutButton" })).toBeEnabled();
  });
});
