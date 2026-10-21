"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchFreshness } from "@/lib/api";

// Une ligne par source ; la couleur de chaque cellule reflète la part de nœuds
// frais (≥ 0.8), en vieillissement (0.2–0.8) ou périmés (< 0.2).
export function FreshnessHeatmap({ tenantId }: { tenantId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["freshness", tenantId],
    queryFn: () => fetchFreshness(tenantId),
    refetchInterval: 30_000,
  });

  if (isLoading) return <p className="text-sm text-slate-500">Chargement de la fraîcheur…</p>;
  if (isError) return <p className="text-sm text-red-600">Fraîcheur indisponible.</p>;
  if (!data || data.length === 0) return <p className="text-sm text-slate-500">Aucune donnée.</p>;

  return (
    <div className="overflow-x-auto rounded-lg border bg-white p-4 shadow-sm">
      <table className="min-w-full text-sm">
        <thead className="text-left text-xs uppercase text-slate-500">
          <tr>
            <th className="px-2 py-1">Source</th>
            <th className="px-2 py-1">Nœuds</th>
            <th className="px-2 py-1">Fraîcheur moy.</th>
            <th className="px-2 py-1">Répartition</th>
          </tr>
        </thead>
        <tbody>
          {data.map((row) => {
            const total = row.nodes || 1;
            return (
              <tr key={row.source}>
                <td className="px-2 py-1 font-medium">{row.source}</td>
                <td className="px-2 py-1">{row.nodes}</td>
                <td className="px-2 py-1">{row.avg_freshness.toFixed(2)}</td>
                <td className="px-2 py-1">
                  <div className="flex h-4 w-64 overflow-hidden rounded bg-slate-100" role="img"
                       aria-label={`${row.fresh} frais, ${row.aging} en vieillissement, ${row.stale} périmés`}>
                    <div className="bg-green-500" style={{ width: `${(row.fresh / total) * 100}%` }} />
                    <div className="bg-amber-400" style={{ width: `${(row.aging / total) * 100}%` }} />
                    <div className="bg-red-500" style={{ width: `${(row.stale / total) * 100}%` }} />
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
