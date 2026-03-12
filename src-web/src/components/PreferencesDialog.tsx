import { useState, useEffect } from "react";
import type { Preferences } from "../hooks/usePreferences";

interface Props {
  preferences: Preferences;
  onSave: (prefs: Preferences) => void;
  onClose: () => void;
}

export default function PreferencesDialog({ preferences, onSave, onClose }: Props) {
  const [local, setLocal] = useState(preferences);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <div
      style={{
        position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex", alignItems: "center", justifyContent: "center",
        zIndex: 10000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: "var(--bg-dialog)",
          border: "1px solid var(--border-color)",
          borderRadius: 8,
          padding: "24px 28px",
          minWidth: Math.min(360, window.innerWidth - 40),
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ fontSize: 15, fontWeight: 600, color: "var(--text-primary)", marginBottom: 20 }}>
          Preferences
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "var(--text-primary)", cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={local.reopenLastFile}
            onChange={(e) => setLocal(prev => ({ ...prev, reopenLastFile: e.target.checked }))}
            style={{ accentColor: "var(--btn-primary)" }}
          />
          Restore previous session on startup
        </label>
        <div style={{ display: "flex", justifyContent: "center", gap: 10, marginTop: 24 }}>
          <button
            onClick={onClose}
            style={{
              padding: "6px 16px",
              background: "var(--bg-input)",
              color: "var(--text-primary)",
              border: "1px solid var(--border-color)",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 13,
            }}
          >
            Cancel
          </button>
          <button
            onClick={() => { onSave(local); onClose(); }}
            style={{
              padding: "6px 16px",
              background: "var(--btn-primary)",
              color: "#fff",
              border: "none",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 13,
            }}
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
