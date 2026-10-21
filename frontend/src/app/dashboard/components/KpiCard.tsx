// Classes complètes (pas de concaténation dynamique) pour que Tailwind les détecte.
const COLORS = {
  blue: "border-blue-200 text-blue-700",
  red: "border-red-200 text-red-700",
  orange: "border-orange-200 text-orange-700",
  green: "border-green-200 text-green-700",
} as const;

export type KpiColor = keyof typeof COLORS;

export function KpiCard({
  label,
  value,
  loading,
  color,
}: {
  label: string;
  value: number | string;
  loading: boolean;
  color: KpiColor;
}) {
  return (
    <div className={`rounded-lg border bg-white p-4 shadow-sm ${COLORS[color]}`}>
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-2 text-3xl font-semibold">{loading ? "…" : value}</p>
    </div>
  );
}
