import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { SettingsSnapshot } from "../types/bridge";
import FloatBarSettingsSection from "./SettingsSection";

vi.mock("../hooks/useLocale", () => ({
  useLocale: () => ({ t: (key: string) => key }),
}));

const settings = {
  floatBarEnabled: true,
  floatBarOpacity: 90,
  floatBarScale: 100,
  floatBarOrientation: "horizontal",
  floatBarStyle: "floating",
  floatBarShowCost: false,
  claudeDailyRoutinesUsageVisible: true,
  claudeAllowReadingClaudeCodeCredentials: false,
  alibabaTokenPlanRegion: "cn",
  weeklyProgressWorkDays: null,
  floatBarShowResetInline: false,
  floatBarDarkText: false,
  floatBarClickThrough: false,
} as unknown as SettingsSnapshot;

describe("FloatBar settings", () => {
  it("uses the existing toggle to turn the taskbar bar off", () => {
    const set = vi.fn();
    render(<FloatBarSettingsSection settings={{ ...settings, floatBarStyle: "taskbar" }} saving={false} set={set} />);
    fireEvent.click(screen.getByRole("checkbox", { name: "FloatBarShowFloatingBar" }));
    expect(set).toHaveBeenCalledWith({ floatBarEnabled: false });
  });

  it("disables the style selector while the bar is off", () => {
    render(<FloatBarSettingsSection settings={{ ...settings, floatBarEnabled: false }} saving={false} set={vi.fn()} />);
    expect(screen.getByRole("combobox", { name: "FloatBarStyle" })).toBeDisabled();
  });

  it("renders one cost toggle", () => {
    render(
      <FloatBarSettingsSection settings={settings} saving={false} set={vi.fn()} />,
    );

    expect(screen.getAllByText("FloatBarShowCost")).toHaveLength(1);
  });
});
