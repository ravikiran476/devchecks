// Core Web Vitals collection with PerformanceObserver. installVitalsObserver is
// self-contained (no imports or closures) so Playwright can inject it with addInitScript.

export interface VitalsSnapshot {
  /** Largest Contentful Paint, ms. */
  lcp?: number;
  /** Cumulative Layout Shift (largest session window). */
  cls?: number;
  /** Interaction to Next Paint, ms (needs real interactions). */
  inp?: number;
  /** First Contentful Paint, ms. */
  fcp?: number;
  /** Time to First Byte, ms. */
  ttfb?: number;
  /** Total Blocking Time after FCP, ms (lab proxy for responsiveness). */
  tbt?: number;
  /** Number of interactions seen (INP is only meaningful when > 0). */
  interactions: number;
  /** Element that produced the LCP, when known. */
  lcpElement?: string;
}

export interface VitalsHandle {
  get(): VitalsSnapshot;
  stop(): void;
}

export function installVitalsObserver(): VitalsHandle {
  const w = window as unknown as { __perfcheck?: VitalsHandle };
  if (w.__perfcheck) return w.__perfcheck;
  const state = { lcp: undefined as number | undefined, lcpElement: undefined as string | undefined, cls: 0, sessionValue: 0, sessionEntries: [] as Array<{ startTime: number }>, fcp: undefined as number | undefined, tbt: 0, longTasks: [] as Array<{ start: number; duration: number }>, interactions: new Map<number, number>() };
  const observers: PerformanceObserver[] = [];
  const observe = (type: string, cb: (entries: PerformanceEntry[]) => void, opts: Record<string, unknown> = {}) => {
    try {
      const o = new PerformanceObserver((list) => cb(list.getEntries()));
      o.observe({ type, buffered: true, ...opts } as PerformanceObserverInit);
      observers.push(o);
    } catch {
      // entry type not supported in this browser
    }
  };
  const describe = (el: Element | null | undefined) => {
    if (!el) return undefined;
    const id = el.id ? `#${el.id}` : '';
    const cls = typeof el.className === 'string' && el.className.trim() ? `.${el.className.trim().split(/\s+/).slice(0, 2).join('.')}` : '';
    return `${el.tagName.toLowerCase()}${id}${cls}`;
  };
  observe('largest-contentful-paint', (entries) => {
    const last = entries[entries.length - 1] as PerformanceEntry & { element?: Element; renderTime?: number; loadTime?: number };
    if (last) {
      state.lcp = last.renderTime || last.loadTime || last.startTime;
      state.lcpElement = describe(last.element);
    }
  });
  observe('layout-shift', (entries) => {
    for (const e of entries as Array<PerformanceEntry & { value: number; hadRecentInput: boolean }>) {
      if (e.hadRecentInput) continue;
      const first = state.sessionEntries[0];
      const last = state.sessionEntries[state.sessionEntries.length - 1];
      // Session windows: gaps under 1 s, total under 5 s.
      if (last && first && e.startTime - last.startTime < 1000 && e.startTime - first.startTime < 5000) {
        state.sessionValue += e.value;
        state.sessionEntries.push(e);
      } else {
        state.sessionValue = e.value;
        state.sessionEntries = [e];
      }
      state.cls = Math.max(state.cls, state.sessionValue);
    }
  });
  observe('paint', (entries) => {
    for (const e of entries) if (e.name === 'first-contentful-paint') state.fcp = e.startTime;
  });
  observe('longtask', (entries) => {
    for (const e of entries) state.longTasks.push({ start: e.startTime, duration: e.duration });
  });
  observe(
    'event',
    (entries) => {
      for (const e of entries as Array<PerformanceEntry & { interactionId?: number }>) {
        if (!e.interactionId) continue;
        state.interactions.set(e.interactionId, Math.max(state.interactions.get(e.interactionId) ?? 0, e.duration));
      }
    },
    { durationThreshold: 16 },
  );
  const handle: VitalsHandle = {
    get() {
      const nav = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
      const durations = [...state.interactions.values()].sort((a, b) => b - a);
      // INP: worst interaction, ignoring one outlier per 50 interactions.
      const inp = durations.length ? durations[Math.min(durations.length - 1, Math.floor(durations.length / 50))] : undefined;
      const fcp = state.fcp ?? 0;
      const tbt = state.longTasks.reduce((sum, t) => (t.start + t.duration > fcp ? sum + Math.max(0, t.duration - 50) : sum), 0);
      return {
        lcp: state.lcp,
        lcpElement: state.lcpElement,
        cls: Math.round(state.cls * 1000) / 1000,
        inp,
        fcp: state.fcp,
        ttfb: nav ? Math.max(0, nav.responseStart - nav.startTime) : undefined,
        tbt,
        interactions: durations.length,
      };
    },
    stop() {
      observers.forEach((o) => o.disconnect());
    },
  };
  w.__perfcheck = handle;
  return handle;
}

export interface ResourceSummary {
  requests: number;
  totalBytes: number;
  byType: Record<'script' | 'stylesheet' | 'image' | 'font' | 'document' | 'other', number>;
  thirdPartyBytes: number;
  largest: Array<{ url: string; bytes: number; type: string }>;
}

/** Self-contained so it can run inside page.evaluate. */
export function collectResources(): ResourceSummary {
  const origin = location.origin;
  const typeOf = (e: PerformanceResourceTiming): keyof ResourceSummary['byType'] => {
    const url = e.name.split('?')[0]!.toLowerCase();
    if (e.initiatorType === 'script' || /\.(m?js)$/.test(url)) return 'script';
    if (e.initiatorType === 'css' || e.initiatorType === 'link' && /\.css$/.test(url) || /\.css$/.test(url)) return 'stylesheet';
    if (e.initiatorType === 'img' || e.initiatorType === 'image' || /\.(png|jpe?g|gif|webp|avif|svg|ico)$/.test(url)) return 'image';
    if (/\.(woff2?|ttf|otf|eot)$/.test(url)) return 'font';
    return 'other';
  };
  const entries = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
  const nav = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
  const byType = { script: 0, stylesheet: 0, image: 0, font: 0, document: 0, other: 0 };
  let thirdPartyBytes = 0;
  const sized = entries.map((e) => {
    const bytes = e.transferSize || e.encodedBodySize || 0;
    const type = typeOf(e);
    byType[type] += bytes;
    try {
      if (new URL(e.name).origin !== origin) thirdPartyBytes += bytes;
    } catch {
      // ignore
    }
    return { url: e.name, bytes, type };
  });
  const docBytes = nav ? nav.transferSize || nav.encodedBodySize || 0 : 0;
  byType.document = docBytes;
  return {
    requests: entries.length + 1,
    totalBytes: sized.reduce((s, r) => s + r.bytes, 0) + docBytes,
    byType,
    thirdPartyBytes,
    largest: sized.sort((a, b) => b.bytes - a.bytes).slice(0, 5),
  };
}
