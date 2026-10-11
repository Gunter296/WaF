"use client";
import { FluentProvider, webDarkTheme, webLightTheme } from "@fluentui/react-components";
import { useEffect, useState } from "react";

export function FinanceProvider({ children }: { children: React.ReactNode }) {
  const [dark, setDark] = useState(false);
  useEffect(() => {
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const update = () => setDark(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  return <FluentProvider theme={dark ? webDarkTheme : webLightTheme}>{children}</FluentProvider>;
}
