import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import type { LocaleKey } from "../../../../../i18n/keys";
import type { AntigravityOAuthStatus } from "../../../../../types/bridge";
import {
  antigravityOAuthCancelLogin,
  antigravityOAuthLogin,
  antigravityOAuthLogout,
  getAntigravityOAuthStatus,
  openPath,
} from "../../../../../lib/tauri";

interface Props {
  t: (key: LocaleKey) => string;
}

/**
 * Google OAuth credentials panel for Antigravity.
 * Lets users sign in, cancel in-flight sign-in, open the stored credentials
 * location, or sign out of `~/.codexbar/antigravity/oauth_creds.json`.
 */
export function AntigravityCreds({ t }: Props) {
  const [status, setStatus] = useState<AntigravityOAuthStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [signingIn, setSigningIn] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const refresh = () => {
      void getAntigravityOAuthStatus()
        .then((next) => {
          if (!cancelled) {
            setStatus(next);
          }
        })
        .catch((err) => {
          if (!cancelled) {
            setError(String(err));
          }
        });
    };
    refresh();
    let unlisten: (() => void) | undefined;
    void listen("antigravity-oauth-updated", refresh)
      .then((fn) => {
        if (cancelled) {
          fn();
        } else {
          unlisten = fn;
        }
      })
      .catch(() => {
        /* ignore outside Tauri shell */
      });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  if (!status) return null;

  const statusLabel = status.signedIn
    ? t("CredsStatusAuthenticated")
    : t("CredsStatusNotSignedIn");

  const handleSignIn = async () => {
    setError(null);
    setNotice(null);
    setBusy(true);
    setSigningIn(true);
    try {
      const next = await antigravityOAuthLogin();
      setStatus(next);
      setNotice(t("CredsAntigravitySignedInNotice"));
    } catch (err) {
      setError(String(err));
    } finally {
      setSigningIn(false);
      setBusy(false);
    }
  };

  const handleCancel = () => {
    void antigravityOAuthCancelLogin().catch((err) => setError(String(err)));
  };

  const handleSignOut = async () => {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const next = await antigravityOAuthLogout();
      setStatus(next);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleOpenFolder = () => {
    if (!status.credentialsPath) return;
    void openPath(status.credentialsPath).catch((err) => setError(String(err)));
  };

  return (
    <section className="provider-detail-section">
      <h4>{t("CredentialsSectionTitle")}</h4>
      <dl className="provider-detail-grid">
        <div style={{ display: "contents" }}>
          <dt>{t("CredsAntigravityLabel")}</dt>
          <dd>
            {statusLabel}
            {status.signedIn && status.email ? ` (${status.email})` : ""}
          </dd>
        </div>
        {status.credentialsPath && (
          <div style={{ display: "contents" }}>
            <dt>{t("CredsAntigravityHelperPrefix")}</dt>
            <dd className="provider-detail-grid__mono">
              {status.credentialsPath}
            </dd>
          </div>
        )}
      </dl>
      {!status.signedIn && (
        <div className="provider-detail-helper">
          {status.clientAvailable
            ? t("CredsAntigravitySetupHelp")
            : (status.missingClientMessage ?? t("CredsAntigravitySetupHelp"))}
        </div>
      )}
      {signingIn && <p role="status">{t("CredsAntigravitySigningIn")}</p>}
      {notice && (
        <div className="provider-detail-note" role="status">
          {notice}
        </div>
      )}
      {error && (
        <div className="provider-detail-error" role="alert">
          {error}
        </div>
      )}
      <div className="provider-detail-actions">
        <button
          type="button"
          className="credential-btn credential-btn--primary"
          disabled={busy || (!status.signedIn && !status.clientAvailable)}
          onClick={() => void handleSignIn()}
        >
          {status.signedIn
            ? t("CredsAntigravityReauthenticateButton")
            : t("CredsAntigravitySignInButton")}
        </button>
        {signingIn && (
          <button
            type="button"
            className="btn btn--ghost"
            onClick={handleCancel}
          >
            {t("CredsAntigravityCancelLogin")}
          </button>
        )}
        {status.signedIn && (
          <button
            type="button"
            className="credential-btn credential-btn--danger"
            disabled={busy}
            onClick={() => void handleSignOut()}
          >
            {t("CredsAntigravitySignOutButton")}
          </button>
        )}
        {status.signedIn && status.credentialsPath && (
          <button
            type="button"
            className="btn btn--ghost"
            disabled={busy}
            onClick={handleOpenFolder}
          >
            {t("CredsOpenFolderAction")}
          </button>
        )}
      </div>
    </section>
  );
}
