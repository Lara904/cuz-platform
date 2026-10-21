"use client";

import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import { useEffect, useRef } from "react";

// Règles dont les nœuds/arêtes sont rendus en rouge. Le guide cite ATTACK-PATH-001 ;
// la version réalisable en Phase 1 est ATTACK-PATH-001-PARTIAL.
export const ATTACK_PATH_RULES = new Set(["ATTACK-PATH-001", "ATTACK-PATH-001-PARTIAL"]);

const STYLE: cytoscape.StylesheetJsonBlock[] = [
  { selector: "node", style: {
      "background-color": "#2980B9", label: "data(name)", "font-size": "10px",
      color: "#1e293b", "text-valign": "bottom", "text-margin-y": 4 } },
  { selector: "node[node_type = 'USER']", style: { "background-color": "#8E44AD" } },
  { selector: "node[node_type = 'STORAGE']", style: { "background-color": "#E67E22" } },
  { selector: "node[node_type = 'REPOSITORY']", style: { "background-color": "#16A085" } },
  { selector: "node.attack-path", style: { "background-color": "#E74C3C", "border-width": 3, "border-color": "#C0392B" } },
  { selector: "edge", style: { "curve-style": "bezier", "target-arrow-shape": "triangle",
      "line-color": "#BDC3C7", "target-arrow-color": "#BDC3C7", width: 1, label: "data(edge_type)", "font-size": "8px" } },
  { selector: "edge.attack-path", style: { "line-color": "#E74C3C", "target-arrow-color": "#E74C3C", width: 3 } },
];

export function GraphCanvas({
  elements,
  attackNodeIds,
  onNodeClick,
}: {
  elements: ElementDefinition[];
  attackNodeIds: Set<string>;
  onNodeClick: (id: string) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const onClick = useRef(onNodeClick);
  onClick.current = onNodeClick;

  // Création unique de l'instance
  useEffect(() => {
    if (!container.current) return;
    cy.current = cytoscape({ container: container.current, style: STYLE, wheelSensitivity: 0.2 });
    cy.current.on("tap", "node", (evt) => onClick.current(evt.target.id()));
    return () => { cy.current?.destroy(); cy.current = null; };
  }, []);

  // Mise à jour des éléments (filtres, rechargement) et marquage des chemins d'attaque
  useEffect(() => {
    const core = cy.current;
    if (!core) return;
    core.elements().remove();
    core.add(elements.map((el) => {
      const isAttack = el.data.source !== undefined
        ? attackNodeIds.has(el.data.source as string) && attackNodeIds.has(el.data.target as string)
        : attackNodeIds.has(el.data.id as string);
      return { ...el, classes: isAttack ? "attack-path" : "" };
    }));
    core.layout({ name: "cose", animate: false }).run();
  }, [elements, attackNodeIds]);

  return <div ref={container} className="h-[600px] w-full rounded-lg border bg-white" />;
}
