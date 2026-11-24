"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { DoraRegisterTable } from "./components/DoraRegisterTable";
import { ConcentrationRiskPanel } from "./components/ConcentrationRiskPanel";
import { fetchDoraRegister, fetchDoraConcentrationRisk, downloadDoraEsaCsv } from "@/lib/api";

const TENANT = "acmecorp";

export default function DoraCompliancePage() {
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const { data: registerData, isLoading: registerLoading, error: registerError } = useQuery({
    queryKey: ["dora-register", TENANT],
    queryFn: () => fetchDoraRegister(TENANT),
  });

  const { data: riskData, isLoading: riskLoading } = useQuery({
    queryKey: ["dora-concentration-risk", TENANT],
    queryFn: () => fetchDoraConcentrationRisk(TENANT),
  });

  async function handleExport() {
    setExporting(true);
    setExportError(null);
    try {
      await downloadDoraEsaCsv(TENANT);
    } catch {
      setExportError("Export impossible. Vérifier le token et les droits d'accès.");
    } finally {
      setExporting(false);
    }
  }

  return (
    <main className="mx-auto max-w-7xl space-y-8 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-slate-800">Conformité DORA — AcmeCorp</h1>
        <button
          onClick={handleExport}
          disabled={exporting}
          className="rounded bg-slate-800 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
        >
          {exporting ? "Export en cours…" : "Exporter (format ESA)"}
        </button>
      </div>

      {exportError && (
        <p className="rounded border border-red-300 bg-red-50 p-3 text-sm text-red-800">{exportError}</p>
      )}

      {registerError && (
        <p className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800">
          API inaccessible ou non authentifiée. Renseigner un token dans localStorage (clé « cuz_token »).
        </p>
      )}

      <section>
        <h2 className="mb-3 text-lg font-semibold">Risque de concentration ICT (DORA Art. 29)</h2>
        <ConcentrationRiskPanel findings={riskData?.findings ?? []} loading={riskLoading} />
      </section>

      <section>
        <h2 className="mb-3 text-lg font-semibold">Registre des tiers</h2>
        <DoraRegisterTable providers={registerData?.register ?? []} loading={registerLoading} />
        <p className="mt-2 text-xs text-slate-500">
          Les fonctions supportées proviennent des arêtes SUPPORTS actuellement dans le graphe
          (chargement manuel tant que le mapping CMDB ServiceNow n&apos;est pas en place).
        </p>
      </section>
    </main>
  );
}
