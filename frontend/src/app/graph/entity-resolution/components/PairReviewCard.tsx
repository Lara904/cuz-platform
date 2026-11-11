import type { ErNode, ErPair } from "@/lib/api";

function NodeColumn({ node, other }: { node: ErNode; other: ErNode }) {
  // Attributs communs aux deux nœuds : surlignés selon qu'ils concordent ou non
  const keys = [...new Set([...Object.keys(node.attributes), ...Object.keys(other.attributes)])].sort();
  return (
    <div className="min-w-0 space-y-2">
      <h3 className="break-all font-semibold">{node.name}</h3>
      <dl className="grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1 text-sm">
        <dt className="text-slate-500">Type</dt><dd>{node.node_type}</dd>
        <dt className="text-slate-500">Sources</dt><dd>{(node.sources ?? []).join(", ") || "—"}</dd>
        <dt className="text-slate-500">Confiance</dt><dd>{Math.round(node.confidence_score * 100)}%</dd>
        <dt className="text-slate-500">Fraîcheur</dt><dd>{Math.round(node.freshness_score * 100)}%</dd>
        <dt className="text-slate-500">ID</dt><dd className="break-all text-xs">{node.id}</dd>
        {keys.map((k) => {
          const mine = JSON.stringify(node.attributes[k]);
          const same = mine !== undefined && mine === JSON.stringify(other.attributes[k]);
          return (
            <div key={k} className="contents">
              <dt className="text-slate-500">{k}</dt>
              <dd className={`break-all ${same ? "text-emerald-700" : ""}`}>
                {mine === undefined ? "—" : mine}
              </dd>
            </div>
          );
        })}
      </dl>
    </div>
  );
}

export function PairReviewCard({ pair, busy, onMerge, onReject, onFlag }: {
  pair: ErPair;
  busy: boolean;
  onMerge: () => void;
  onReject: () => void;
  onFlag: () => void;
}) {
  return (
    <article className="rounded-lg border bg-white p-4 shadow-sm">
      <header className="mb-3 flex items-center justify-between">
        <span className="text-sm text-slate-600">
          Probabilité de doublon : <strong>{Math.round(pair.match_probability * 100)}%</strong>
          {pair.flagged && <span className="ml-2 rounded bg-amber-100 px-2 py-0.5 text-amber-800">signalée</span>}
        </span>
        <span className="font-mono text-xs text-slate-400">{pair.pair_id}</span>
      </header>
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <NodeColumn node={pair.node_a} other={pair.node_b} />
        <NodeColumn node={pair.node_b} other={pair.node_a} />
      </div>
      <footer className="mt-4 flex gap-2">
        <button disabled={busy} onClick={onMerge}
          className="rounded bg-emerald-600 px-3 py-1 text-sm text-white disabled:opacity-50">Fusionner</button>
        <button disabled={busy} onClick={onReject}
          className="rounded bg-slate-600 px-3 py-1 text-sm text-white disabled:opacity-50">Rejeter</button>
        <button disabled={busy} onClick={onFlag}
          className="rounded border border-amber-500 px-3 py-1 text-sm text-amber-700 disabled:opacity-50">Signaler</button>
      </footer>
    </article>
  );
}
