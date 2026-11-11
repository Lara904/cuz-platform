"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, decidePair, fetchErDecisionStats, fetchPendingPairs, type ErDecision } from "@/lib/api";
import { PairReviewCard } from "./components/PairReviewCard";

const TENANT = "acmecorp";

export default function EntityResolutionPage() {
  const queryClient = useQueryClient();
  const pairs = useQuery({ queryKey: ["er-pairs", TENANT], queryFn: () => fetchPendingPairs(TENANT) });
  const stats = useQuery({ queryKey: ["er-stats", TENANT], queryFn: () => fetchErDecisionStats(TENANT) });

  const mutation = useMutation({
    mutationFn: ({ pairId, decision }: { pairId: string; decision: ErDecision }) =>
      decidePair(TENANT, pairId, decision),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["er-pairs", TENANT] });
      queryClient.invalidateQueries({ queryKey: ["er-stats", TENANT] });
    },
  });

  const noModel = pairs.error instanceof ApiError && pairs.error.status === 409;
  const forbidden = mutation.error instanceof ApiError && mutation.error.status === 403;

  return (
    <main className="space-y-6 p-6">
      <h1 className="text-2xl font-bold text-slate-800">
        CUz — Validation Entity Resolution ({pairs.data?.total ?? 0} paires en attente)
      </h1>
      <p className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">
        Zone grise 60–92 %. La décision « Fusionner » est enregistrée (audit append-only) et servira à
        recalibrer le modèle ; <strong>la fusion n&apos;est pas encore appliquée dans le graphe</strong>.
      </p>
      {stats.data && (
        <p className="text-sm text-slate-600">
          Paires traitées : {stats.data.total_reviewed} — fusionnées {stats.data.merged}, rejetées{" "}
          {stats.data.rejected}, signalées {stats.data.flagged}
        </p>
      )}
      {pairs.isLoading && <p>Chargement…</p>}
      {noModel && <p className="text-slate-600">Modèle ER non entraîné pour ce tenant.</p>}
      {pairs.isError && !noModel && <p className="text-red-700">Erreur de chargement des paires.</p>}
      {forbidden && <p className="text-red-700">Décision refusée : le rôle OPERATOR est requis.</p>}
      {pairs.data?.total === 0 && <p className="text-slate-600">Aucune paire en attente de validation.</p>}
      <div className="space-y-4">
        {(pairs.data?.pairs ?? []).map((pair) => (
          <PairReviewCard
            key={pair.pair_id}
            pair={pair}
            busy={mutation.isPending}
            onMerge={() => mutation.mutate({ pairId: pair.pair_id, decision: "merge" })}
            onReject={() => mutation.mutate({ pairId: pair.pair_id, decision: "reject" })}
            onFlag={() => mutation.mutate({ pairId: pair.pair_id, decision: "flag" })}
          />
        ))}
      </div>
    </main>
  );
}
