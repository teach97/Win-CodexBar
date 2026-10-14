import { Field, Select, Toggle } from "../components/FormControls";
import { useDraftNumber } from "../hooks/useDraftNumber";
import { useLocale } from "../hooks/useLocale";
import type {
  FloatBarOrientation,
  FloatBarStyle,
  SettingsSnapshot,
  SettingsUpdate,
} from "../types/bridge";

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
  const commitOpacity = () => {
    opacity.commit(opacity.draft, (value) => set({ floatBarOpacity: value }));
  };
  const commitScale = () => {
    scale.commit(scale.draft, (value) => set({ floatBarScale: value }));
  };
  const commitFontSize = () => {
    fontSize.commit(fontSize.draft, (value) => set({ floatBarFontSize: value }));
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
            value={settings.floatBarOrientation}
            disabled={saving || !settings.floatBarEnabled}
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
