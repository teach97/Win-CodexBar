import type { CSSProperties } from "react";
import { ProviderIcon } from "../components/providers/ProviderIcon";
import { useLocale } from "../hooks/useLocale";
import { describeProviderState } from "../lib/providerState";
import type { ProviderUsageSnapshot } from "../types/bridge";

interface Props {
  provider: ProviderUsageSnapshot;
  scale: number;
  fontSize: number;
  colorGradient: boolean;
  canDrag?: boolean;
  style: CSSProperties;
}

export default function TaskbarQuotaPill({ provider, scale, fontSize, colorGradient, canDrag = true, style }: Props) {
  const { t } = useLocale();
  const state = describeProviderState(provider.errorState);
  const remainingLabel = t("FloatBarRemainingSuffix");
  const windows = [provider.primary, provider.secondary];
  const periods = [
    { minutes: 300, label: t("PanelFiveHours") },
    { minutes: 7 * 24 * 60, label: t("ProviderWeekly") },
  ] as const;
  const rows = periods.map(({ minutes, label }) => {
    const window = windows.find(window => window?.windowMinutes === minutes);
    const remaining = window && !window.isInformational && Number.isFinite(window.remainingPercent)
      ? Math.max(0, Math.min(100, window.remainingPercent))
      : null;
    const value = remaining === null ? "—" : `${Math.round(remaining)}%`;
    const color = colorGradient && remaining !== null ? `hsl(${remaining * 1.2}, 85%, 60%)` : undefined;
    return { label, value, color };
  });

  return (
    <div
      className={`floatbar__pill floatbar__pill--stacked${state.isProblem ? " floatbar__pill--crit" : ""}`}
      title={state.isProblem
        ? `${provider.displayName}: ${t(state.labelKey)}`
        : `${provider.displayName}\n${rows.map(row => `${row.label}: ${row.value} ${remainingLabel}`).join("\n")}`}
      data-tauri-drag-region={canDrag || undefined}
      style={style}
    >
      <span className="floatbar__provider-icon" data-tauri-drag-region={canDrag || undefined}>
        <ProviderIcon providerId={provider.providerId} size={Math.round(fontSize * 2 * scale)} />
      </span>
      {state.isProblem ? (
        <span className="floatbar__pct" aria-label={t(state.labelKey)} data-tauri-drag-region={canDrag || undefined}>!</span>
      ) : (
        <span className="floatbar__quota-values" data-tauri-drag-region={canDrag || undefined}>
          {rows.map(row => (
            <span
              key={row.label}
              className="floatbar__quota-row"
              style={{ color: row.color }}
              aria-label={`${row.label} ${remainingLabel}`}
              data-tauri-drag-region={canDrag || undefined}
            >
              {row.value}
            </span>
          ))}
        </span>
      )}
    </div>
  );
}
