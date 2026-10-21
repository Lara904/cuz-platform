import type { Finding } from "@/lib/api";

const SEVERITY_STYLE: Record<Finding["severity"], string> = {
  CRITICAL: "bg-red-100 text-red-800",
  HIGH: "bg-orange-100 text-orange-800",
  MEDIUM: "bg-yellow-100 text-yellow-800",
  LOW: "bg-blue-100 text-blue-800",
  INFO: "bg-slate-100 text-slate-700",
};

export function FindingsTable({ findings, loading }: { findings: Finding[]; loading: boolean }) {
  if (loading) return <p className="text-sm text-slate-500">Chargement des findings…</p>;
  if (findings.length === 0) return <p className="text-sm text-slate-500">Aucun finding ouvert.</p>;
  return (
    <div className="overflow-x-auto rounded-lg border bg-white shadow-sm">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead className="bg-slate-50 text-left text-xs uppercase text-slate-500">
          <tr>
            <th className="px-3 py-2">Sévérité</th>
            <th className="px-3 py-2">Règle</th>
            <th className="px-3 py-2">Titre</th>
            <th className="px-3 py-2">Nœuds</th>
            <th className="px-3 py-2">Confiance</th>
            <th className="px-3 py-2">Remédiation</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {findings.map((f) => (
            <tr key={f.id} className="align-top">
              <td className="px-3 py-2">
                <span className={`rounded px-2 py-0.5 text-xs font-medium ${SEVERITY_STYLE[f.severity]}`}>
                  {f.severity}
                </span>
              </td>
              <td className="whitespace-nowrap px-3 py-2 font-mono text-xs">{f.rule_id}</td>
              <td className="px-3 py-2">{f.title}</td>
              <td className="px-3 py-2 text-slate-600">{f.affected_node_names.join(", ")}</td>
              <td className="whitespace-nowrap px-3 py-2">{Math.round(f.confidence_score * 100)}%</td>
              <td className="px-3 py-2 text-slate-600">{f.remediation_hint}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
