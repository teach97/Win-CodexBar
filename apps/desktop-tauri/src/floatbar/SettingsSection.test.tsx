import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SettingsSnapshot } from "../types/bridge";
import FloatBarSettingsSection from "./SettingsSection";

const apiMocks = vi.hoisted(() => ({ getFloatBarTaskbars: vi.fn() }));
vi.mock("./api", () => apiMocks);

vi.mock("../hooks/useLocale", () => ({
  useLocale: () => ({ t: (key: string) => key }),
}));

const settings = {
  floatBarEnabled: true,
  floatBarOpacity: 90,
  floatBarScale: 100,
  floatBarFontSize: 14,
  floatBarColorGradient: true,
  floatBarTaskbarDocked: false,
  floatBarTaskbarMonitor: "",
  floatBarTaskbarPosition: 10,
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
  beforeEach(() => {
    apiMocks.getFloatBarTaskbars.mockResolvedValue([
      { id: "display-1", name: "Display 1", primary: true, width: 1920, height: 1080 },
      { id: "display-2", name: "Display 2", primary: false, width: 2560, height: 1440 },
    ]);
  });

  it.each([true, false])("toggles actual taskbar docking from %s", (docked) => {
    const set = vi.fn();
    render(<FloatBarSettingsSection settings={{ ...settings, floatBarStyle: "taskbar", floatBarTaskbarDocked: docked }} saving={false} set={set} />);
    const toggle = screen.getByRole("checkbox", { name: "FloatBarTaskbarDocked" });
    expect(toggle).toHaveProperty("checked", docked);
    fireEvent.click(toggle);
    expect(set).toHaveBeenCalledWith({ floatBarTaskbarDocked: !docked });
  });

  it("selects a discovered taskbar without replacing the automatic primary choice", async () => {
    const set = vi.fn();
    render(<FloatBarSettingsSection settings={{ ...settings, floatBarStyle: "taskbar", floatBarTaskbarDocked: true }} saving={false} set={set} />);
    const select = screen.getByRole("combobox", { name: "FloatBarTaskbarMonitor" });
    await waitFor(() => expect(screen.getByRole("option", { name: "Display 2 (2560 × 1440)" })).toBeInTheDocument());
    expect(select).toHaveValue("");
    fireEvent.change(select, { target: { value: "display-2" } });
    expect(set).toHaveBeenCalledWith({ floatBarTaskbarMonitor: "display-2" });
  });

  it("retains a disconnected saved monitor until another selection is made", async () => {
    const set = vi.fn();
    render(<FloatBarSettingsSection settings={{ ...settings, floatBarStyle: "taskbar", floatBarTaskbarDocked: true, floatBarTaskbarMonitor: "disconnected" }} saving={false} set={set} />);
    const select = screen.getByRole("combobox", { name: "FloatBarTaskbarMonitor" });
    await waitFor(() => expect(screen.getByRole("option", { name: "Display 1 (1920 × 1080)" })).toBeInTheDocument());
    expect(select).toHaveValue("disconnected");
    expect(screen.getByRole("option", { name: "FloatBarTaskbarMonitorUnavailable (disconnected)" })).toBeInTheDocument();
    expect(set).not.toHaveBeenCalled();
  });

  it("commits the taskbar position after dragging and locks the orientation", () => {
    const set = vi.fn();
    render(<FloatBarSettingsSection settings={{ ...settings, floatBarStyle: "taskbar", floatBarTaskbarDocked: true, floatBarTaskbarPosition: 10 }} saving={false} set={set} />);
    const slider = screen.getByRole("slider", { name: "FloatBarTaskbarPosition" });
    fireEvent.change(slider, { target: { value: "72" } });
    expect(set).not.toHaveBeenCalled();
    fireEvent.pointerUp(slider);
    expect(set).toHaveBeenCalledWith({ floatBarTaskbarPosition: 72 });
    expect(screen.getByRole("combobox", { name: "FloatBarOrientation" })).toBeDisabled();
  });

  it("disables monitor and position controls while undocked", () => {
    render(<FloatBarSettingsSection settings={{ ...settings, floatBarStyle: "taskbar", floatBarTaskbarDocked: false }} saving={false} set={vi.fn()} />);
    expect(screen.getByRole("combobox", { name: "FloatBarTaskbarMonitor" })).toBeDisabled();
    expect(screen.getByRole("slider", { name: "FloatBarTaskbarPosition" })).toBeDisabled();
  });

  it.each([true, false])("toggles the persisted gradient from %s", (enabled) => {
    const set = vi.fn();
    render(<FloatBarSettingsSection settings={{ ...settings, floatBarStyle: "taskbar", floatBarColorGradient: enabled }} saving={false} set={set} />);
    const toggle = screen.getByRole("checkbox", { name: "FloatBarColorGradient" });
    expect(toggle).toHaveProperty("checked", enabled);
    fireEvent.click(toggle);
    expect(set).toHaveBeenCalledWith({ floatBarColorGradient: !enabled });
  });

  it("commits a taskbar font size independently of the overall scale", () => {
    const set = vi.fn();
    render(<FloatBarSettingsSection settings={{ ...settings, floatBarStyle: "taskbar" }} saving={false} set={set} />);
    const slider = screen.getByRole("slider", { name: "FloatBarFontSize" });
    fireEvent.change(slider, { target: { value: "18" } });
    expect(set).not.toHaveBeenCalled();
    fireEvent.pointerUp(slider);
    expect(set).toHaveBeenCalledWith({ floatBarFontSize: 18 });
  });

  it("disables the taskbar font control for the floating style", () => {
    render(<FloatBarSettingsSection settings={settings} saving={false} set={vi.fn()} />);
    expect(screen.getByRole("slider", { name: "FloatBarFontSize" })).toBeDisabled();
  });

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
