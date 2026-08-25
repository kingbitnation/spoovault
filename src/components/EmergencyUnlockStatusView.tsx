import { Chip } from "@heroui/react";
import {
  describeEmergencyUnlock,
  EmergencyUnlockLoadState,
  EmergencyUnlockScheduleView,
} from "../utils/emergencyUnlockStatus";

interface EmergencyUnlockStatusViewProps {
  emergencyMode: boolean;
  schedule: EmergencyUnlockScheduleView | undefined;
  loadState?: EmergencyUnlockLoadState;
}

export function EmergencyUnlockStatusView({
  emergencyMode,
  schedule,
  loadState = "ready",
}: EmergencyUnlockStatusViewProps) {
  const status = describeEmergencyUnlock(emergencyMode, schedule, loadState);

  return (
    <div className="space-y-1">
      <Chip
        size="sm"
        variant="flat"
        color={loadState === "error" ? "danger" : emergencyMode ? "warning" : "default"}
        data-testid="emergency-unlock-status"
      >
        {status.label}
      </Chip>
      {status.detail && (
        <p className="text-amber-200/90 text-xs" data-testid="emergency-unlock-detail">
          {status.detail}
        </p>
      )}
    </div>
  );
}
