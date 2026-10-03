// Shared class vocabulary for modals and cards.
//
// Two rules hold everything together:
//   1. Surfaces are a violet-tinted scrim (violet-950/30…/50), never a pale fill — the light
//      theme's field runs purple-900 → orange-900, where a pale tint drops below 2:1. The tint
//      keeps a badge reading as darkened glass instead of a hole cut through the card.
//   2. Muted text uses text-white/NN, never text-theme-primary/NN: `text-theme-primary`
//      is hand-written CSS in index.css, so Tailwind emits nothing for its slash variants
//      and the element silently falls back to the inherited (dark) colour.

export const MODAL_OVERLAY =
  'fixed inset-0 bg-black/60 flex items-center justify-center animate-fade-in modal-overlay-high';
export const MODAL_SURFACE = 'bg-theme-modal-gradient rounded-lg p-8';
export const MODAL_HEADER = 'flex items-center justify-between gap-4 mb-4';
export const MODAL_TITLE = 'text-2xl font-bold text-theme-primary';
export const MODAL_CLOSE =
  'rounded-md p-1 text-white/70 transition-colors hover:bg-white/10 hover:text-theme-primary';

// Vertical rhythm stays with the caller — cards and modals space these differently.
export const SECTION_LABEL =
  "flex items-center gap-2 text-[10.5px] font-bold uppercase tracking-[0.09em] text-white/70 after:h-px after:flex-1 after:bg-white/15 after:content-['']";

export const TUF_BADGE_STYLE = {
  'all-signed': { label: 'TUF signed', badge: 'text-green-300 border-green-500/40', dot: 'bg-green-500', hint: 'Every artifact is signed' },
  partial: { label: 'TUF partial', badge: 'text-amber-300 border-amber-500/45', dot: 'bg-amber-500', hint: 'Some artifacts are not signed yet' },
  none: { label: 'TUF unsigned', badge: 'text-red-300 border-red-500/45', dot: 'bg-red-500', hint: 'No artifact is signed' },
} as const;

export type TufStatus = keyof typeof TUF_BADGE_STYLE;

export const STATUS_BADGE =
  'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[13px] font-semibold bg-violet-950/50 border';
export const STATUS_DOT = 'w-[7px] h-[7px] rounded-full shrink-0';

export const PLATFORM_CHIP =
  'inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[13px] bg-violet-950/50 border border-white/20 text-theme-primary hover:bg-violet-950/65 transition-colors';

export const ROW =
  'flex items-center justify-between gap-3 rounded-lg border border-white/15 bg-violet-950/30 px-3 py-2.5';
export const ROW_TILE = 'flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-white/10';
export const ROW_TITLE = 'truncate text-[14.5px] font-bold text-theme-primary';
export const ROW_META = 'flex flex-wrap items-center gap-2 font-mono text-[11.5px] text-white/60';

export const ACTION_GROUP =
  'inline-flex shrink-0 items-center gap-px rounded-lg border border-white/20 bg-violet-950/50 p-0.5';
export const ACTION_BUTTON = 'rounded-md px-2 py-1.5 transition-colors duration-200';

export const FIELD_LABEL = 'mb-2 block text-xs font-semibold text-white/70';
export const FIELD_INPUT =
  'w-full rounded-lg border border-white/15 bg-violet-950/30 px-3 py-2 text-theme-primary transition-all duration-150 placeholder:text-white/40 focus:outline-none focus:ring-2 focus:ring-theme-focus';

export const DROPDOWN_TRIGGER =
  'flex w-full min-w-0 items-center justify-between rounded-lg border border-white/15 bg-violet-950/30 p-2 pr-3 text-theme-primary transition-colors hover:bg-violet-950/50';
export const DROPDOWN_MENU =
  'absolute top-full left-0 right-0 mt-1 rounded-lg border border-white/15 shadow-lg z-[90]';
export const DROPDOWN_OPTION =
  'flex w-full items-center gap-2 truncate px-4 py-2 text-left text-theme-primary transition-colors hover:bg-white/10 first:rounded-t-lg last:rounded-b-lg';
export const DROPDOWN_MENU_STYLE = {
  background: 'var(--dropdown-bg)',
  backdropFilter: 'blur(20px)',
  WebkitBackdropFilter: 'blur(20px)',
  boxShadow: '0 16px 40px rgba(15, 23, 42, 0.35)',
};

export const BTN_GHOST =
  'rounded-lg border border-white/25 px-4 py-2 font-semibold text-theme-primary transition-colors hover:bg-white/10 disabled:cursor-not-allowed disabled:opacity-50';
export const BTN_PRIMARY =
  'rounded-lg bg-theme-button-submit px-4 py-2 font-semibold text-theme-primary transition-colors disabled:cursor-not-allowed disabled:opacity-50';
export const BTN_DANGER =
  'rounded-lg bg-red-600 px-4 py-2 font-semibold text-white transition-colors hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50';
export const BTN_WARNING =
  'flex w-full items-center justify-center gap-2 rounded-lg border border-amber-500/55 bg-violet-950/50 px-3 py-2 text-[13px] font-bold text-amber-300 transition-colors hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-50';

export const DROPZONE =
  'flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg border border-dashed border-white/30 bg-white/5 px-4 py-4 text-sm text-white/85 transition-colors hover:bg-white/10';

export const NOTE_WARNING =
  'flex items-center gap-3 rounded-lg border border-amber-500/45 bg-violet-950/40 px-3 py-3 text-sm text-amber-300';

export const MARKDOWN_PREVIEW =
  'prose prose-sm prose-invert max-w-none rounded-lg border border-white/15 bg-violet-950/30 p-4';

export const SEGMENTED_GROUP = 'inline-flex overflow-hidden rounded-md border border-white/20';
export const segmentedButton = (active: boolean, withDivider = false) =>
  `${withDivider ? 'border-l border-white/20 ' : ''}px-3 py-1 text-xs font-semibold transition-colors ${
    active ? 'bg-white/15 text-theme-primary' : 'bg-violet-950/30 text-white/70 hover:bg-white/10'
  }`;
