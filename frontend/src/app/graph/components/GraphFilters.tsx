"use client";

export interface Filters {
  nodeTypes: Set<string>;
  sources: Set<string>;
  minConfidence: number;
}

export function GraphFilters({
  nodeTypes,
  sources,
  value,
  onChange,
}: {
  nodeTypes: string[];
  sources: string[];
  value: Filters;
  onChange: (f: Filters) => void;
}) {
  const toggle = (set: Set<string>, item: string) => {
    const next = new Set(set);
    if (next.has(item)) next.delete(item);
    else next.add(item);
    return next;
  };

  return (
    <div className="space-y-4 rounded-lg border bg-white p-4 text-sm shadow-sm">
      <fieldset>
        <legend className="mb-2 font-semibold">Type de nœud</legend>
        <div className="flex flex-wrap gap-2">
          {nodeTypes.map((t) => (
            <label key={t} className="flex items-center gap-1">
              <input type="checkbox" checked={value.nodeTypes.has(t)}
                     onChange={() => onChange({ ...value, nodeTypes: toggle(value.nodeTypes, t) })} />
              {t}
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset>
        <legend className="mb-2 font-semibold">Source</legend>
        <div className="flex flex-wrap gap-2">
          {sources.map((s) => (
            <label key={s} className="flex items-center gap-1">
              <input type="checkbox" checked={value.sources.has(s)}
                     onChange={() => onChange({ ...value, sources: toggle(value.sources, s) })} />
              {s}
            </label>
          ))}
        </div>
      </fieldset>
      <label className="block">
        <span className="font-semibold">Confiance minimale : {Math.round(value.minConfidence * 100)}%</span>
        <input type="range" min={0} max={1} step={0.05} value={value.minConfidence} className="w-full"
               onChange={(e) => onChange({ ...value, minConfidence: Number(e.target.value) })} />
      </label>
    </div>
  );
}
