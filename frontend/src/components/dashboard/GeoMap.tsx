import { useMemo, useState, type MouseEvent, type PointerEvent, type ReactNode } from "react";
import { Maximize2, Minus, Plus } from "lucide-react";
import type { ThreatEvent } from "@/lib/sentinel-data";

const WIDTH = 900;
const HEIGHT = 360;

const tierColor = {
  Low: "var(--tier-low)",
  Medium: "var(--tier-medium)",
  High: "var(--tier-high)",
} as const;

const tierRadius = { Low: 4, Medium: 5, High: 7 } as const;

const landForms = [
  "M145 115c34-42 96-44 139-18 31 18 47 49 35 80-10 25-43 28-68 36-32 10-43 43-81 31-40-13-61-45-55-78 3-18 16-36 30-51Z",
  "M258 238c33-8 73 4 89 31 20 33-5 71-34 86-24 12-54 2-61-24-7-25-32-31-28-56 3-18 15-32 34-37Z",
  "M394 122c29-36 80-44 127-34 38 8 58 35 84 57 19 16 51 9 73 21 36 20 35 64 9 88-25 24-72 13-103 3-34-11-63-8-97-1-47 9-92-13-106-51-11-31-7-59 13-83Z",
  "M572 252c30-14 79-7 94 26 17 37-17 64-51 55-28-8-54-42-43-81Z",
  "M696 140c43-22 97-10 135 14 29 19 42 54 25 83-15 25-48 22-76 26-35 5-57 28-93 16-44-14-54-62-31-100 9-15 23-30 40-39Z",
  "M733 285c20-11 52-6 70 9 18 16 23 42 6 58-24 22-76 15-92-15-9-19-4-41 16-52Z",
  "M501 272c27-8 58 6 74 28 19 27 10 66-21 80-34 16-72-9-81-44-6-25 3-55 28-64Z",
] as const;

interface Hover {
  ev: ThreatEvent;
  x: number;
  y: number;
}

function projectPoint(lat: number, lng: number) {
  const safeLat = Math.max(-80, Math.min(84, lat));
  const x = ((lng + 180) / 360) * WIDTH;
  const rad = (safeLat * Math.PI) / 180;
  const mercN = Math.log(Math.tan(Math.PI / 4 + rad / 2));
  const y = HEIGHT / 2 - (WIDTH * mercN) / (2 * Math.PI);
  return { x, y };
}

function MapShell({ children, count }: { children: ReactNode; count: number }) {
  return (
    <section className="card-soft fade-in-up p-6">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          Attacker IP Geolocation
        </h2>
        <span className="text-xs text-muted-foreground">
          Total IPs Plotted: <span className="font-mono-sec text-foreground">{count}</span>
        </span>
      </div>
      {children}
    </section>
  );
}

export function GeoMap({ events }: { events: ThreatEvent[] }) {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [drag, setDrag] = useState<{ x: number; y: number; panX: number; panY: number } | null>(null);
  const [hover, setHover] = useState<Hover | null>(null);

  const points = useMemo(() => events.slice(0, 80).map((ev) => ({ ev, ...projectPoint(ev.lat, ev.lng) })), [events]);
  const reset = () => { setZoom(1); setPan({ x: 0, y: 0 }); };
  const zoomIn = () => setZoom((value) => Math.min(4, value * 1.35));
  const zoomOut = () => setZoom((value) => Math.max(1, value / 1.35));
  const moveHover = (evt: MouseEvent<SVGCircleElement>, ev: ThreatEvent) => {
    const rect = evt.currentTarget.ownerSVGElement?.getBoundingClientRect();
    setHover({ ev, x: evt.clientX - (rect?.left ?? 0), y: evt.clientY - (rect?.top ?? 0) });
  };
  const beginDrag = (evt: PointerEvent<SVGSVGElement>) => {
    evt.currentTarget.setPointerCapture(evt.pointerId);
    setDrag({ x: evt.clientX, y: evt.clientY, panX: pan.x, panY: pan.y });
  };
  const onDrag = (evt: PointerEvent<SVGSVGElement>) => {
    if (!drag) return;
    setPan({ x: drag.panX + (evt.clientX - drag.x) / zoom, y: drag.panY + (evt.clientY - drag.y) / zoom });
  };

  return (
    <MapShell count={events.length}>
      <div className="relative h-[320px] w-full overflow-hidden rounded-2xl border border-border bg-background">
        <div className="absolute left-3 top-3 z-10 flex flex-col overflow-hidden rounded-lg border border-border bg-card shadow-sm">
          <button type="button" onClick={zoomIn} className="grid h-8 w-8 place-items-center text-muted-foreground transition-colors hover:bg-muted hover:text-foreground" aria-label="Zoom in">
            <Plus className="h-4 w-4" />
          </button>
          <button type="button" onClick={zoomOut} className="grid h-8 w-8 place-items-center border-t border-border text-muted-foreground transition-colors hover:bg-muted hover:text-foreground" aria-label="Zoom out">
            <Minus className="h-4 w-4" />
          </button>
          <button type="button" onClick={reset} className="grid h-8 w-8 place-items-center border-t border-border text-muted-foreground transition-colors hover:bg-muted hover:text-foreground" aria-label="Reset view">
            <Maximize2 className="h-3.5 w-3.5" />
          </button>
        </div>

        <svg
          className="h-full w-full cursor-grab touch-none active:cursor-grabbing"
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          role="img"
          aria-label="World map showing attacker IP locations"
          onPointerDown={beginDrag}
          onPointerMove={onDrag}
          onPointerUp={() => setDrag(null)}
          onPointerCancel={() => setDrag(null)}
          onMouseLeave={() => { setDrag(null); setHover(null); }}
        >
          <defs>
            <pattern id="map-grid" width="45" height="45" patternUnits="userSpaceOnUse">
              <path d="M45 0H0V45" fill="none" stroke="var(--border)" strokeOpacity="0.5" strokeWidth="0.75" />
            </pattern>
          </defs>
          <rect width={WIDTH} height={HEIGHT} fill="var(--background)" />
          <rect width={WIDTH} height={HEIGHT} fill="url(#map-grid)" opacity="0.55" />
          <g transform={`translate(${WIDTH / 2} ${HEIGHT / 2}) scale(${zoom}) translate(${-WIDTH / 2 + pan.x} ${-HEIGHT / 2 + pan.y})`} className="transition-transform duration-300 ease-out">
            {landForms.map((path) => (
              <path key={path} d={path} fill="var(--border)" stroke="var(--card)" strokeWidth="1.5" opacity="0.95" />
            ))}
            {points.map(({ ev, x, y }, index) => {
              const color = tierColor[ev.tier];
              const radius = tierRadius[ev.tier];
              return (
                <g key={ev.id} className="fade-in" style={{ animationDelay: `${index * 18}ms` }}>
                  <circle cx={x} cy={y} r={radius * 2.4} fill={color} opacity="0.14" className="map-marker-pulse" />
                  <circle
                    cx={x}
                    cy={y}
                    r={radius}
                    fill={color}
                    stroke="var(--card)"
                    strokeWidth="1.25"
                    className="cursor-pointer"
                    onMouseEnter={(evt) => moveHover(evt, ev)}
                    onMouseMove={(evt) => moveHover(evt, ev)}
                    onMouseLeave={() => setHover(null)}
                  />
                </g>
              );
            })}
          </g>
        </svg>

        {hover && (
          <div className="pointer-events-none absolute z-20 -translate-x-1/2 -translate-y-full rounded-xl border border-border bg-card px-3 py-2 text-xs shadow-lg fade-in" style={{ left: hover.x, top: hover.y - 12 }}>
            <div className="font-mono-sec font-semibold">{hover.ev.ip}</div>
            <div className="text-muted-foreground">{hover.ev.city}, {hover.ev.country}</div>
            <div className="font-semibold" style={{ color: tierColor[hover.ev.tier] }}>{hover.ev.tier} Threat</div>
            <div className="font-mono-sec text-muted-foreground">Score: {hover.ev.score.toFixed(3)}</div>
          </div>
        )}
      </div>

      <div className="mt-4 flex items-center justify-center gap-5 text-xs text-muted-foreground">
        {(["Low", "Medium", "High"] as const).map((tier) => (
          <span key={tier} className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: tierColor[tier], boxShadow: `0 0 8px ${tierColor[tier]}` }} />
            {tier}
          </span>
        ))}
      </div>
    </MapShell>
  );
}
