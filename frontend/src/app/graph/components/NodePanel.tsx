import type { GraphNode } from "@/lib/api";

export function NodePanel({ node, onClose }: { node: GraphNode | null; onClose: () => void }) {
  if (!node) {
    return <p className="text-sm text-slate-500">Cliquer un nœud pour voir son détail.</p>;
  }
  return (
    <aside className="space-y-3 rounded-lg border bg-white p-4 text-sm shadow-sm">
      <div className="flex items-start justify-between">
        <h3 className="font-semibold break-all">{node.name}</h3>
        <button onClick={onClose} className="text-slate-400 hover:text-slate-700" aria-label="Fermer">✕</button>
      </div>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1">
        <dt className="text-slate-500">Type</dt><dd>{node.node_type}</dd>
        <dt className="text-slate-500">Sources</dt><dd>{(node.sources ?? []).join(", ") || "—"}</dd>
        <dt className="text-slate-500">Confiance</dt><dd>{Math.round(node.confidence_score * 100)}%</dd>
        <dt className="text-slate-500">Fraîcheur</dt><dd>{Math.round(node.freshness_score * 100)}%</dd>
        <dt className="text-slate-500">Owner</dt><dd>{node.owner ?? "—"}</dd>
      </dl>
      <details>
        <summary className="cursor-pointer text-slate-600">Attributs</summary>
        <pre className="mt-2 max-h-64 overflow-auto rounded bg-slate-50 p-2 text-xs">
          {JSON.stringify(node.attributes, null, 2)}
        </pre>
      </details>
    </aside>
  );
}
