import { useQuery } from "@tanstack/react-query";
import React, { useEffect } from "react";
import { useNavigate } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { StateView } from "../../shared/ui";

/** Completes the server-side OIDC callback without exposing tokens to browser storage. */
export function OidcCallbackPage(): React.JSX.Element {
  const api = useRed2PrApi();
  const navigate = useNavigate();
  const session = useQuery({
    queryKey: ["me", "oidc-callback"],
    queryFn: () => api.getMe(),
    retry: false,
  });

  useEffect(() => {
    if (session.isSuccess) void navigate("/account", { replace: true });
    if (session.isError) void navigate("/login", { replace: true });
  }, [navigate, session.isError, session.isSuccess]);

  return <StateView state="loading" />;
}
