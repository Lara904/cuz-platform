import type { DoraProvider } from "@/lib/api";

const EXIT_PLAN_STYLE: Record<string, string> = {
  NOT_SET: "bg-red-100 text-red-800",
  draft: "bg-yellow-100 text-yellow-800",
  documented: "bg-green-100 text-green-800",
};

export function DoraRegisterTable({ providers, loading }: { providers: DoraProvider[]; loading: boolean }) {
  if (loading) return <p className="text-sm text-slate-500">Chargement du registre…</p>;
  if (providers.length === 0) return <p className="text-sm text-slate-500">Aucun prestataire tiers enregistré.</p>;
  return (
    <div className="overflow-x-auto rounded-lg border bg-white shadow-sm">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead className="bg-slate-50 text-left text-xs uppercase text-slate-500">
          <tr>
            <th className="px-3 py-2">Prestataire</th>
            <th className="px-3 py-2">Type</th>
            <th className="px-3 py-2">Plan de sortie</th>
            <th className="px-3 py-2">Dernière révision</th>
            <th className="px-3 py-2">Fonctions supportées</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {providers.map((p) => (
            <tr key={p.provider_name} className="align-top">
              <td className="px-3 py-2 font-medium text-slate-800">{p.provider_name}</td>
              <td className="px-3 py-2 text-slate-600">{p.provider_type || "—"}</td>
              <td className="px-3 py-2">
                <span
                  className={`rounded px-2 py-0.5 text-xs font-medium ${
                    EXIT_PLAN_STYLE[p.exit_plan_status] ?? "bg-slate-100 text-slate-700"
                  }`}
                >
                  {p.exit_plan_status}
                </span>
              </td>
              <td className="whitespace-nowrap px-3 py-2 text-slate-600">{p.last_review_date || "—"}</td>
              <td className="px-3 py-2 text-slate-600">
                {p.supported_functions.length > 0 ? p.supported_functions.join(", ") : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
