"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchTimeline } from "@/lib/api";

// Source : table finding_audit (append-only). Plus récent en premier.
export function MutationTimeline({ tenantId }: { tenantId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["timeline", tenantId],
    queryFn: () => fetchTimeline(tenantId),
    refetchInterval: 30_000,
  });

  if (isLoading) return <p className="text-sm text-slate-500">Chargement de la timeline…</p>;
  if (isError) return <p className="text-sm text-red-600">Timeline indisponible.</p>;
  if (!data || data.length === 0) return <p className="text-sm text-slate-500">Aucune mutation enregistrée.</p>;

  return (
    <div className="overflow-x-auto rounded-lg border bg-white shadow-sm">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead className="bg-slate-50 text-left text-xs uppercase text-slate-500">
          <tr>
            <th className="px-3 py-2">Date</th>
            <th className="px-3 py-2">Règle</th>
            <th className="px-3 py-2">Action</th>
            <th className="px-3 py-2">Acteur</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {data.map((e, i) => (
            <tr key={`${e.finding_id}-${e.created_at}-${i}`}>
              <td className="whitespace-nowrap px-3 py-2 text-slate-600">
                {new Date(e.created_at).toLocaleString("fr-FR")}
              </td>
              <td className="whitespace-nowrap px-3 py-2 font-mono text-xs">{e.rule_id}</td>
              <td className="px-3 py-2">{e.action}</td>
              <td className="px-3 py-2">{e.actor}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
