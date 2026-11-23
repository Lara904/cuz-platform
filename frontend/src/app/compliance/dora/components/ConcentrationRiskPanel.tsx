import type { Finding } from "@/lib/api";

export function ConcentrationRiskPanel({ findings, loading }: { findings: Finding[]; loading: boolean }) {
  if (loading) return <p className="text-sm text-slate-500">Analyse du risque de concentration…</p>;
  if (findings.length === 0) {
    return (
      <p className="rounded border border-green-300 bg-green-50 p-3 text-sm text-green-800">
        Aucun prestataire ne supporte 3 fonctions critiques ou plus (DORA Art. 29).
      </p>
    );
  }
  return (
    <div className="space-y-3">
      {findings.map((f) => (
        <div key={f.id} className="rounded border border-orange-300 bg-orange-50 p-3 text-sm text-orange-900">
          <p className="font-semibold">{f.title}</p>
          <p className="mt-1">
            <strong>{f.affected_node_names.join(", ")}</strong> — {f.remediation_hint}
          </p>
        </div>
      ))}
    </div>
  );
}
