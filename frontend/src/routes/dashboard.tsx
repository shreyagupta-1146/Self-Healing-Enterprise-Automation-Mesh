import { createFileRoute } from "@tanstack/react-router";
import { Dashboard } from "@/components/dashboard/Dashboard";

export const Route = createFileRoute("/dashboard")({
  component: Dashboard,
  head: () => ({
    meta: [
      { title: "SentiHealth — Operations Dashboard" },
      {
        name: "description",
        content: "Live threat detection and audit overview for SentiHealth.",
      },
    ],
  }),
});
