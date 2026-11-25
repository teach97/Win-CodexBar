use codexbar::core::ProviderId;
use codexbar::providers::antigravity::login::{self, AntigravityOAuthStatus};
use std::sync::Mutex;
use tauri::{Emitter, Manager};

use super::invalidate_account_usage;
use crate::state::AppState;

static LOGIN_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn emit_antigravity_oauth_updated(app: &tauri::AppHandle) {
    let _emit = app.emit("antigravity-oauth-updated", ());
    let handle = app.clone();
    let _dispatch = app.run_on_main_thread(move || crate::tray_bridge::rebuild_tray_menu(&handle));
}

#[tauri::command]
pub fn antigravity_oauth_status() -> AntigravityOAuthStatus {
    login::status()
}

#[tauri::command]
pub async fn antigravity_oauth_login(
    app: tauri::AppHandle,
) -> Result<AntigravityOAuthStatus, String> {
    let _guard = LOGIN_MUTEX
        .try_lock()
        .map_err(|_| "An Antigravity Google sign-in is already in progress.")?;
    login::login_with_browser(crate::commands::system::open_url_in_browser).await?;

    crate::auto_resume::clear(&app, ProviderId::Antigravity);
    {
        let state = app.state::<Mutex<AppState>>();
        let mut state = state.lock().map_err(|e| e.to_string())?;
        let pending = invalidate_account_usage(&mut state, ProviderId::Antigravity);
        crate::events::emit_provider_updated(&app, &pending);
    }
    if let Err(err) = super::do_refresh_providers_with_outcome(&app).await {
        tracing::warn!(%err, "Antigravity refresh after Google OAuth sign-in failed");
    }
    emit_antigravity_oauth_updated(&app);
    Ok(login::status())
}

#[tauri::command]
pub fn antigravity_oauth_cancel_login() {
    login::cancel_login();
}

#[tauri::command]
pub async fn antigravity_oauth_logout(
    app: tauri::AppHandle,
) -> Result<AntigravityOAuthStatus, String> {
    let _guard = LOGIN_MUTEX
        .try_lock()
        .map_err(|_| "An Antigravity Google sign-in is already in progress.")?;
    login::sign_out()?;
    crate::auto_resume::clear(&app, ProviderId::Antigravity);
    {
        let state = app.state::<Mutex<AppState>>();
        let mut state = state.lock().map_err(|e| e.to_string())?;
        let pending = invalidate_account_usage(&mut state, ProviderId::Antigravity);
        crate::events::emit_provider_updated(&app, &pending);
    }
    if let Err(err) = super::do_refresh_providers_with_outcome(&app).await {
        tracing::debug!(%err, "Antigravity refresh after Google OAuth sign-out failed");
    }
    emit_antigravity_oauth_updated(&app);
    Ok(login::status())
}
