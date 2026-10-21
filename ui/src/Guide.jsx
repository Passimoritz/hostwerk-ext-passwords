/*
 * Guide "Install the extension in <browser>" as step cards with small moving drawings (switch flips, folder opens, cable
 * connects) – and a connected picture as soon as the extension paired itself. Pure SVG/CSS, respects "reduce motion".
 */
import { Check } from 'lucide-react';
import { t } from '@hostwerk/i18n';

const Art = {
  page: () => (
    <svg viewBox="0 0 64 44" className="xg-art" aria-hidden="true"><rect x="2" y="3" width="60" height="38" rx="5" className="xg-frame" /><path d="M2 12h60" className="xg-line" /><circle cx="8" cy="7.5" r="1.6" className="xg-dot" /><circle cx="13" cy="7.5" r="1.6" className="xg-dot" /><rect x="8" y="18" width="20" height="16" rx="3" className="xg-card xg-pop" /><rect x="34" y="18" width="22" height="5" rx="2" className="xg-bar" /><rect x="34" y="27" width="15" height="5" rx="2" className="xg-bar" /></svg>
  ),
  toggle: () => (
    <svg viewBox="0 0 64 44" className="xg-art" aria-hidden="true"><rect x="2" y="3" width="60" height="38" rx="5" className="xg-frame" /><text x="8" y="17" className="xg-txt">{t('Developer')}</text><rect x="38" y="22" width="20" height="11" rx="5.5" className="xg-toggle" /><circle cx="43.5" cy="27.5" r="4" className="xg-knob" /></svg>
  ),
  folder: () => (
    <svg viewBox="0 0 64 44" className="xg-art" aria-hidden="true"><path d="M10 12h14l4 4h26v20a3 3 0 0 1-3 3H13a3 3 0 0 1-3-3z" className="xg-card" /><path d="M10 19h44l-5 20H13z" className="xg-lid" /><path d="m27 28 4 4 8-8" className="xg-tick" /></svg>
  ),
  add: () => (
    <svg viewBox="0 0 64 44" className="xg-art" aria-hidden="true"><rect x="8" y="6" width="48" height="32" rx="6" className="xg-frame" /><rect x="30" y="25" width="20" height="8" rx="3" className="xg-btn xg-pop" /><path d="M14 14h22M14 20h14" className="xg-line" /></svg>
  ),
  plug: () => (
    <svg viewBox="0 0 64 44" className="xg-art" aria-hidden="true"><rect x="3" y="14" width="16" height="16" rx="4" className="xg-card" /><rect x="45" y="14" width="16" height="16" rx="4" className="xg-card xg-acc" /><path d="M19 22h26" className="xg-wire" /></svg>
  ),
};

/** steps: [{ art, title, text }] · waiting: the last step pulses · done: everything ticked */
export function ExtGuide({ steps, waiting, done }) {
  return (
    <ol className={`xg ${done ? 'done' : ''}`}>
      {steps.map((s, i) => {
        const A = Art[s.art] || Art.page;
        const last = i === steps.length - 1;
        return (
          <li key={i} className={`xg-step ${last && waiting && !done ? 'wait' : ''}`} style={{ animationDelay: `${i * 70}ms` }}>
            <div className="xg-pic"><A /><span className="xg-n">{done ? <Check size={11} /> : i + 1}</span></div>
            <div className="xg-tx"><b>{s.title}</b>{s.text && <span>{s.text}</span>}</div>
          </li>
        );
      })}
    </ol>
  );
}

/** Connected picture: browser ↔ Hostwerk, the line draws itself, a tick appears. */
export function ExtLinked({ name, browser }) {
  return (
    <div className="xl" role="status">
      <svg viewBox="0 0 220 70" className="xl-art" aria-hidden="true">
        <rect x="6" y="14" width="56" height="42" rx="9" className="xl-node" />
        <circle cx="34" cy="35" r="11" className="xl-globe" /><path d="M23 35h22M34 24a17 17 0 0 1 0 22M34 24a17 17 0 0 0 0 22" className="xl-globe" />
        <path d="M62 35h96" className="xl-wire" />
        <circle cx="110" cy="35" r="13" className="xl-ok" /><path d="m104 35 4.5 4.5 8-8.5" className="xl-tick" />
        <rect x="158" y="14" width="56" height="42" rx="9" className="xl-node xl-hw" />
        <circle cx="181" cy="40" r="6" className="xl-key" /><path d="m185 36 10-10M192 29l3 3" className="xl-key" />
      </svg>
      <div><b>{t('{name} is connected to Hostwerk', { name: name || browser })}</b><span>{t('Pin the Hostwerk icon in the browser bar – from now on suggestions show up right in the sign-in field.')}</span></div>
    </div>
  );
}

/** The fitting steps per way of installing. */
export function extSteps({ mode, fx, label, registered }) {
  if (mode === 'store') return [
    { art: 'add', title: t('Click “Add” in {label}', { label }), text: t('The page of the extension in the store is already open.') },
    ...(registered ? [{ art: 'page', title: t('Tab closed? No problem'), text: t('On the next start of {label} the browser asks by itself – click “Enable” there.', { label }) }] : []),
    { art: 'plug', title: t('Connects by itself'), text: t('Hostwerk waits for the extension.') },
  ];
  if (mode === 'signed' || fx) return [
    { art: 'add', title: t('Firefox asks → “Add”'), text: mode === 'signed' ? '' : t('If Firefox refuses the unsigned file: about:debugging → “Load temporary add-on” → choose the .xpi.') },
    { art: 'plug', title: t('Connects by itself'), text: t('Hostwerk waits for the extension.') },
  ];
  return [
    { art: 'page', title: t('The extension page is open'), text: t('{label} shows its extensions.', { label }) },
    { art: 'toggle', title: t('Switch on “Developer mode”'), text: label === 'Edge' ? t('Switch on the left in the bar.') : t('Switch at the top right.') },
    { art: 'folder', title: t('“Load unpacked”'), text: t('Choose the folder – the path is already on the clipboard (Ctrl+V into the address field of the dialog).') },
    { art: 'plug', title: t('Connects by itself'), text: t('No code needed – Hostwerk waits for the extension.') },
  ];
}

/**
 * Markenfarben der Browser – bewusst fest: Sie stehen nur im kleinen Browser-Zeichen (wie ein Logo) und helfen, den
 * eigenen Browser in der Liste wiederzuerkennen. Nie für Knöpfe, Text oder Zustände – dafür gilt die Akzentfarbe.
 */
export const BROWSER_COLORS = { chrome: '#34a853', edge: '#0ea5e9', firefox: '#ff7139', brave: '#fb542b', opera: '#ff1b2d', vivaldi: '#ef3939', safari: '#1d9bf0' };

/** Small browser mark (colour circle + first letter) for lists – decoration only (aria-hidden), the name stands next to it. */
export function BrowserMark({ id, size = 22 }) {
  return <span className="br-mark" style={{ width: size, height: size, background: BROWSER_COLORS[id] || 'var(--muted)' }} aria-hidden="true">{(id || '?')[0].toUpperCase()}</span>;
}
