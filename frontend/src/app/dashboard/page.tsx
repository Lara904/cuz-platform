"use client";

import { useQuery } from "@tanstack/react-query";
import { KpiCard } from "./components/KpiCard";
import { FindingsTable } from "./components/FindingsTable";
import { FreshnessHeatmap } from "./components/FreshnessHeatmap";
import { MutationTimeline } from "./components/MutationTimeline";
import { fetchStats, fetchFindings } from "@/lib/api";

const TENANT = "acmecorp";

export default function DashboardPage() {
  const { data: stats, isLoading: statsLoading, error: statsError } = useQuery({
    queryKey: ["stats", TENANT],
    queryFn: () => fetchStats(TENANT),
    refetchInterval: 30_000,
  });

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ["findings", TENANT, "open"],
    queryFn: () => fetchFindings(TENANT, { size: 20, status: "open" }),
    refetchInterval: 30_000,
  });

  return (
    <main className="mx-auto max-w-7xl space-y-8 p-6">
      <h1 className="text-2xl font-bold text-slate-800">CUz — Tableau de bord AcmeCorp</h1>

      {statsError && (
        <p className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800">
          API inaccessible ou non authentifiée. Renseigner un token dans localStorage (clé « cuz_token »).
        </p>
      )}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <KpiCard label="Nœuds total" value={stats?.node_count ?? "---"} loading={statsLoading} color="blue" />
        <KpiCard label="CRITICAL" value={stats?.by_severity?.CRITICAL ?? 0} loading={statsLoading} color="red" />
        <KpiCard label="HIGH" value={stats?.by_severity?.HIGH ?? 0} loading={statsLoading} color="orange" />
        <KpiCard
          label="Qualité des données"
          value={stats?.health_score != null ? `${Math.round(stats.health_score * 100)}%` : "---"}
          loading={statsLoading}
          color="green"
        />
      </div>

      <section>
        <h2 className="mb-3 text-lg font-semibold">Top 20 findings ouverts</h2>
        <FindingsTable findings={findings ?? []} loading={findingsLoading} />
      </section>

      <section>
        <h2 className="mb-3 text-lg font-semibold">Timeline des mutations (20 dernières)</h2>
        <MutationTimeline tenantId={TENANT} />
      </section>

      <section>
        <h2 className="mb-3 text-lg font-semibold">Fraîcheur par source</h2>
        <FreshnessHeatmap tenantId={TENANT} />
      </section>
    </main>
  );
}
