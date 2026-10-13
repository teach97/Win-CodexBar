import type { CSSProperties } from "react";
import { ProviderIcon } from "../components/providers/ProviderIcon";
import { useLocale } from "../hooks/useLocale";
import { describeProviderState } from "../lib/providerState";
import { resolveQuotaWarning, type QuotaWarningSettings } from "../lib/quotaWarnings";
import type { ProviderUsageSnapshot } from "../types/bridge";

interface Props {
  provider: ProviderUsageSnapshot;
  thresholds: QuotaWarningSettings;
  scale: number;
  fontSize: number;
  style: CSSProperties;
}

export default function TaskbarQuotaPill({ provider, thresholds, scale, fontSize, style }: Props) {
  const { t } = useLocale();
  const state = describeProviderState(provider.errorState);
  const remainingLabel = t("FloatBarRemainingSuffix");
  const windows = [provider.primary, provider.secondary];
  const periods = [
    { minutes: 300, label: t("PanelFiveHours"), warningWindow: "session" },
    { minutes: 7 * 24 * 60, label: t("ProviderWeekly"), warningWindow: "weekly" },
  ] as const;
  const rows = periods.map(({ minutes, label, warningWindow }) => {
    const window = windows.find(window => window?.windowMinutes === minutes);
    const remaining = window && !window.isInformational && Number.isFinite(window.remainingPercent)
      ? Math.max(0, Math.min(100, window.remainingPercent))
      : null;
    const value = remaining === null ? "—" : `${Math.round(remaining)}%`;
    const warning = resolveQuotaWarning(thresholds, provider.providerId, warningWindow);
    let tone = "ok";
    if (remaining !== null) {
      if (window?.isExhausted || (warning.enabled && remaining <= 100 - warning.critical)) tone = "crit";
      else if (warning.enabled && remaining <= 100 - warning.high) tone = "warn";
    }
    return { label, value, tone };
  });

  return (
    <div
      className={`floatbar__pill floatbar__pill--stacked${state.isProblem ? " floatbar__pill--crit" : ""}`}
      title={state.isProblem
        ? `${provider.displayName}: ${t(state.labelKey)}`
        : `${provider.displayName}\n${rows.map(row => `${row.label}: ${row.value} ${remainingLabel}`).join("\n")}`}
      data-tauri-drag-region
      style={style}
    >
      <span className="floatbar__provider-icon" data-tauri-drag-region>
        <ProviderIcon providerId={provider.providerId} size={Math.round(fontSize * 2 * scale)} />
      </span>
      {state.isProblem ? (
        <span className="floatbar__pct" aria-label={t(state.labelKey)} data-tauri-drag-region>!</span>
      ) : (
        <span className="floatbar__quota-values" data-tauri-drag-region>
          {rows.map(row => (
            <span
              key={row.label}
              className={`floatbar__quota-row floatbar__quota-row--${row.tone}`}
              aria-label={`${row.label} ${remainingLabel}`}
              data-tauri-drag-region
            >
              {row.value}
            </span>
          ))}
        </span>
      )}
    </div>
  );
}
