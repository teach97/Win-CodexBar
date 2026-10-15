import { useEffect, useState } from "react";
import { Field, Select, Toggle } from "../components/FormControls";
import { useDraftNumber } from "../hooks/useDraftNumber";
import { useLocale } from "../hooks/useLocale";
import type {
  FloatBarOrientation,
  FloatBarStyle,
  SettingsSnapshot,
  SettingsUpdate,
} from "../types/bridge";
import { getFloatBarTaskbars, type FloatBarTaskbar } from "./api";

interface Props {
  settings: SettingsSnapshot;
  saving: boolean;
  set: (patch: SettingsUpdate) => void;
}

/**
 * Settings UI block for the floating capacity bar. Rendered as one row
 * in the Display tab — kept in this module so the Display tab only
 * imports a single component.
 */
export default function FloatBarSettingsSection({ settings, saving, set }: Props) {
  const { t } = useLocale();
  const opacity = useDraftNumber(settings.floatBarOpacity);
  const scale = useDraftNumber(settings.floatBarScale);
  const fontSize = useDraftNumber(settings.floatBarFontSize ?? 14);
  const taskbarPosition = useDraftNumber(settings.floatBarTaskbarPosition ?? 10);
  const docked = settings.floatBarStyle === "taskbar" && settings.floatBarTaskbarDocked;
  const [taskbars, setTaskbars] = useState<FloatBarTaskbar[]>([]);
  useEffect(() => {
    if (!settings.floatBarEnabled || settings.floatBarStyle !== "taskbar") return;
    let cancelled = false;
    void getFloatBarTaskbars().then((available) => {
      if (!cancelled) setTaskbars(available);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, [settings.floatBarEnabled, settings.floatBarStyle, settings.floatBarTaskbarDocked]);
  const monitor = settings.floatBarTaskbarMonitor ?? "";
  const monitorOptions = [
    { value: "", label: t("FloatBarTaskbarPrimaryMonitor") },
    ...taskbars.map((taskbar) => ({
      value: taskbar.id,
      label: `${taskbar.name} (${taskbar.width} × ${taskbar.height})`,
    })),
    ...(monitor && !taskbars.some((taskbar) => taskbar.id === monitor)
      ? [{ value: monitor, label: `${t("FloatBarTaskbarMonitorUnavailable")} (${monitor})` }]
      : []),
  ];
  const commitOpacity = () => {
    opacity.commit(opacity.draft, (value) => set({ floatBarOpacity: value }));
  };
  const commitScale = () => {
    scale.commit(scale.draft, (value) => set({ floatBarScale: value }));
  };
  const commitFontSize = () => {
    fontSize.commit(fontSize.draft, (value) => set({ floatBarFontSize: value }));
  };
  const commitTaskbarPosition = () => {
    taskbarPosition.commit(taskbarPosition.draft, (value) => set({ floatBarTaskbarPosition: value }));
  };

  return (
    <section className="settings-section">
      <h3 className="settings-section__title">{t("FloatBarSectionTitle")}</h3>
      <div className="settings-section__group">
        <Field
          label={t("FloatBarShowFloatingBar")}
          description={t("FloatBarShowFloatingBarHelper")}
          leading
        >
          <Toggle
            checked={settings.floatBarEnabled}
            disabled={saving}
            onChange={(v) => set({ floatBarEnabled: v })}
          />
        </Field>
        <Field
          label={t("FloatBarOrientation")}
          description={t("FloatBarOrientationHelper")}
        >
          <Select
            value={docked ? "horizontal" : settings.floatBarOrientation}
            disabled={saving || !settings.floatBarEnabled || docked}
            options={[
              { value: "horizontal", label: t("FloatBarOrientationHorizontal") },
              { value: "vertical", label: t("FloatBarOrientationVertical") },
            ]}
            onChange={(v) => set({ floatBarOrientation: v as FloatBarOrientation })}
          />
        </Field>
        <Field
          label={t("FloatBarStyle")}
          description={t("FloatBarStyleHelper")}
        >
          <Select
            value={settings.floatBarStyle}
            disabled={saving || !settings.floatBarEnabled}
            options={[
              { value: "floating", label: t("FloatBarStyleFloating") },
              { value: "taskbar", label: t("FloatBarStyleTaskbar") },
            ]}
            onChange={(v) => set({ floatBarStyle: v as FloatBarStyle })}
          />
        </Field>
        {settings.floatBarStyle === "taskbar" && (
          <>
            <Field
              label={t("FloatBarTaskbarDocked")}
              description={t("FloatBarTaskbarDockedHelper")}
              leading
            >
              <Toggle
                checked={settings.floatBarTaskbarDocked ?? false}
                disabled={saving || !settings.floatBarEnabled}
                onChange={(v) => set({ floatBarTaskbarDocked: v })}
              />
            </Field>
            <Field
              label={t("FloatBarTaskbarMonitor")}
              description={t("FloatBarTaskbarMonitorHelper")}
            >
              <Select
                value={monitor}
                disabled={saving || !settings.floatBarEnabled || !docked}
                options={monitorOptions}
                onChange={(v) => set({ floatBarTaskbarMonitor: v })}
              />
            </Field>
            <Field
              label={`${t("FloatBarTaskbarPosition")} (${taskbarPosition.draft}%)`}
              description={t("FloatBarTaskbarPositionHelper")}
            >
              <input
                type="range"
                min={0}
                max={100}
                step={1}
                value={taskbarPosition.draft}
                disabled={saving || !settings.floatBarEnabled || !docked}
                onChange={(e) => taskbarPosition.setDraft(Number(e.target.value))}
                onPointerUp={commitTaskbarPosition}
                onTouchEnd={commitTaskbarPosition}
                onBlur={commitTaskbarPosition}
                onKeyUp={commitTaskbarPosition}
                aria-label={t("FloatBarTaskbarPosition")}
              />
            </Field>
          </>
        )}
        <Field
          label={`${t("FloatBarOpacity")} (${opacity.draft}%)`}
          description={t("FloatBarOpacityHelper")}
        >
          <input
            type="range"
            min={30}
            max={100}
            step={5}
            value={opacity.draft}
            disabled={!settings.floatBarEnabled}
            onChange={(e) => opacity.setDraft(Number(e.target.value))}
            onPointerUp={commitOpacity}
            onTouchEnd={commitOpacity}
            onBlur={commitOpacity}
            onKeyUp={commitOpacity}
            aria-label={t("FloatBarOpacityAriaLabel")}
          />
        </Field>
        <Field
          label={`${t("FloatBarFontSize")} (${fontSize.draft}px)`}
          description={t("FloatBarFontSizeHelper")}
        >
          <input
            type="range"
            min={10}
            max={20}
            step={1}
            value={fontSize.draft}
            disabled={saving || !settings.floatBarEnabled || settings.floatBarStyle !== "taskbar"}
            onChange={(e) => fontSize.setDraft(Number(e.target.value))}
            onPointerUp={commitFontSize}
            onTouchEnd={commitFontSize}
            onBlur={commitFontSize}
            onKeyUp={commitFontSize}
            aria-label={t("FloatBarFontSize")}
          />
        </Field>
        <Field
          label={`${t("FloatBarSize")} (${scale.draft}%)`}
          description={t("FloatBarSizeHelper")}
        >
          <input
            type="range"
            min={75}
            max={200}
            step={5}
            value={scale.draft}
            disabled={!settings.floatBarEnabled}
            onChange={(e) => scale.setDraft(Number(e.target.value))}
            onPointerUp={commitScale}
            onTouchEnd={commitScale}
            onBlur={commitScale}
            onKeyUp={commitScale}
            aria-label={t("FloatBarSizeAriaLabel")}
          />
        </Field>
        <Field
          label={t("FloatBarColorGradient")}
          description={t("FloatBarColorGradientHelper")}
          leading
        >
          <Toggle
            checked={settings.floatBarColorGradient ?? true}
            disabled={saving || !settings.floatBarEnabled || settings.floatBarStyle !== "taskbar"}
            onChange={(v) => set({ floatBarColorGradient: v })}
          />
        </Field>
        <Field
          label={t("FloatBarShowCost")}
          description={t("FloatBarShowCostDescription")}
          leading
        >
          <Toggle
            checked={settings.floatBarShowCost}
            disabled={saving || !settings.floatBarEnabled}
            onChange={(v) => set({ floatBarShowCost: v })}
          />
        </Field>
        <Field
          label={t("FloatBarShowResetInline")}
          description={t("FloatBarShowResetInlineHelper")}
          leading
        >
          <Toggle
            checked={settings.floatBarShowResetInline}
            disabled={saving || !settings.floatBarEnabled}
            onChange={(v) => set({ floatBarShowResetInline: v })}
          />
        </Field>
        <Field
          label={t("FloatBarInvertColors")}
          description={t("FloatBarInvertColorsHelper")}
          leading
        >
          <Toggle
            checked={settings.floatBarDarkText}
            disabled={saving || !settings.floatBarEnabled}
            onChange={(v) => set({ floatBarDarkText: v })}
          />
        </Field>
        <Field
          label={t("FloatBarClickThrough")}
          description={t("FloatBarClickThroughHelper")}
          leading
        >
          <Toggle
            checked={settings.floatBarClickThrough}
            disabled={saving || !settings.floatBarEnabled}
            onChange={(v) => set({ floatBarClickThrough: v })}
          />
        </Field>
      </div>
    </section>
  );
}
