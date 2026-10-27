import React from "react";
import { StateView } from "../shared/ui";

interface AppErrorBoundaryProps {
  readonly children: React.ReactNode;
}

interface AppErrorBoundaryState {
  readonly hasError: boolean;
}

/**
 * Top-level render boundary rendering sanitized UX remediation without
 * exposing raw client/server stack traces (`FE-04`, `SEC-040`).
 */
export class AppErrorBoundary extends React.Component<
  AppErrorBoundaryProps,
  AppErrorBoundaryState
> {
  public override state: AppErrorBoundaryState = { hasError: false };

  public static getDerivedStateFromError(): AppErrorBoundaryState {
    return { hasError: true };
  }

  public override render(): React.ReactNode {
    if (this.state.hasError) {
      return (
        <main style={{ padding: 24 }}>
          <StateView
            state="error"
            primaryAction={{
              label: "Reload application",
              onClick: () => window.location.reload(),
            }}
          />
        </main>
      );
    }
    return this.props.children;
  }
}
