"use client";

import { useQuery } from "@tanstack/react-query";
import type { ElementDefinition } from "cytoscape";
import { useEffect, useMemo, useState } from "react";
import { fetchGraph } from "@/lib/api";
import { ATTACK_PATH_RULES, GraphCanvas } from "./components/GraphCanvas";
import { GraphFilters, type Filters } from "./components/GraphFilters";
import { NodePanel } from "./components/NodePanel";

const TENANT = "acmecorp";

export default function GraphPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["graph", TENANT],
    queryFn: () => fetchGraph(TENANT),
    refetchInterval: 60_000,
  });

  const nodeTypes = useMemo(() => [...new Set(data?.nodes.map((n) => n.node_type) ?? [])].sort(), [data]);
  const sources = useMemo(
    () => [...new Set(data?.nodes.flatMap((n) => n.sources ?? []) ?? [])].sort(),
    [data],
  );

  const [filters, setFilters] = useState<Filters | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Par défaut : tous les types et toutes les sources visibles
  useEffect(() => {
    if (data && filters === null) {
      setFilters({ nodeTypes: new Set(nodeTypes), sources: new Set(sources), minConfidence: 0 });
    }
  }, [data, filters, nodeTypes, sources]);

  const attackNodeIds = useMemo(() => new Set(
    (data?.findings ?? [])
      .filter((f) => ATTACK_PATH_RULES.has(f.rule_id))
      .flatMap((f) => f.affected_nodes),
  ), [data]);

  const visibleNodes = useMemo(() => (data?.nodes ?? []).filter((n) =>
    filters !== null &&
    filters.nodeTypes.has(n.node_type) &&
    (n.sources ?? []).some((s) => filters.sources.has(s)) &&
    n.confidence_score >= filters.minConfidence,
  ), [data, filters]);

  const elements: ElementDefinition[] = useMemo(() => {
    const ids = new Set(visibleNodes.map((n) => n.id));
    const nodeEls = visibleNodes.map((n) => ({
      data: { id: n.id, name: n.name, node_type: n.node_type },
    }));
    const edgeEls = (data?.edges ?? [])
      .filter((e) => ids.has(e.source_id) && ids.has(e.target_id))
      .map((e) => ({
        data: { id: e.id, source: e.source_id, target: e.target_id, edge_type: e.edge_type },
      }));
    return [...nodeEls, ...edgeEls];
  }, [visibleNodes, data]);

  const selected = data?.nodes.find((n) => n.id === selectedId) ?? null;

  return (
    <main className="mx-auto max-w-7xl space-y-6 p-6">
      <h1 className="text-2xl font-bold text-slate-800">Graphe AcmeCorp</h1>
      {isError && <p className="text-sm text-red-600">Graphe indisponible (API ou authentification).</p>}
      {isLoading && <p className="text-sm text-slate-500">Chargement du graphe…</p>}
      {data && filters && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-4">
          <div className="space-y-4 lg:col-span-1">
            <GraphFilters nodeTypes={nodeTypes} sources={sources} value={filters} onChange={setFilters} />
            <NodePanel node={selected} onClose={() => setSelectedId(null)} />
          </div>
          <div className="lg:col-span-3">
            <p className="mb-2 text-xs text-slate-500">
              {visibleNodes.length} nœuds · {elements.length - visibleNodes.length} arêtes ·
              chemins d&apos;attaque en rouge
            </p>
            <GraphCanvas elements={elements} attackNodeIds={attackNodeIds}
                         onNodeClick={(id) => setSelectedId(id)} />
          </div>
        </div>
      )}
    </main>
  );
}
