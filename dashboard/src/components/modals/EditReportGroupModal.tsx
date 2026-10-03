import React, { useState } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { ReportGroup } from '@/hooks/use-query/useReportsQuery';
import {
  BTN_GHOST,
  BTN_PRIMARY,
  FIELD_INPUT,
  FIELD_LABEL,
  MODAL_CLOSE,
  MODAL_HEADER,
  MODAL_OVERLAY,
  MODAL_SURFACE,
  MODAL_TITLE,
  STATUS_BADGE,
} from '@/components/common/ui';

interface EditReportGroupModalProps {
  group: ReportGroup;
  onClose: () => void;
  onConfirm: (data: { tags: string[]; note: string }) => Promise<void>;
}

const formatLabel = (value: string) =>
  value
    .split('_')
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');

export const EditReportGroupModal: React.FC<EditReportGroupModalProps> = ({ group, onClose, onConfirm }) => {
  const [tags, setTags] = useState<string[]>(group.tags ?? []);
  const [tagInput, setTagInput] = useState('');
  const [note, setNote] = useState(group.note ?? '');
  const [isSaving, setIsSaving] = useState(false);

  const backdropProps = useBackdropClose(onClose);

  const addTag = (raw: string) => {
    const value = raw.trim().toLowerCase();
    if (value && !tags.includes(value)) {
      setTags((prev) => [...prev, value]);
    }
    setTagInput('');
  };

  const handleTagKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      addTag(tagInput);
    } else if (e.key === 'Backspace' && !tagInput && tags.length > 0) {
      setTags((prev) => prev.slice(0, -1));
    }
  };

  const removeTag = (tag: string) => {
    setTags((prev) => prev.filter((t) => t !== tag));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const finalTags = tagInput.trim() ? [...tags, tagInput.trim().toLowerCase()] : tags;
    setIsSaving(true);
    try {
      await onConfirm({ tags: Array.from(new Set(finalTags)), note: note.trim() });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className={MODAL_OVERLAY} {...backdropProps}>
      <div className={`${MODAL_SURFACE} w-full max-w-md`}>
        <div className={MODAL_HEADER}>
          <h2 className={MODAL_TITLE}>Edit report group</h2>
          <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <p className="mb-5 text-sm text-white/70">
          {group.application.name} v{group.application.version} · {formatLabel(group.event.type)} / {formatLabel(group.event.reason)}
        </p>

        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className={FIELD_LABEL}>Tags</label>
            {tags.length > 0 && (
              <div className="mb-2 flex flex-wrap gap-1.5">
                {tags.map((tag) => (
                  <span key={tag} className={`${STATUS_BADGE} border-violet-400/50 text-violet-200`}>
                    {tag}
                    <button
                      type="button"
                      onClick={() => removeTag(tag)}
                      className="ml-1 rounded p-0.5 text-white/70 transition-colors hover:bg-white/15 hover:text-red-300"
                      title="Remove tag"
                    >
                      <i className="fas fa-times"></i>
                    </button>
                  </span>
                ))}
              </div>
            )}
            <input
              type="text"
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={handleTagKeyDown}
              onBlur={() => tagInput.trim() && addTag(tagInput)}
              placeholder="Type a tag and press Enter"
              className={FIELD_INPUT}
            />
          </div>

          <div className="mb-6">
            <label className={FIELD_LABEL}>Note</label>
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="e.g. tracked in JIRA-123"
              rows={3}
              className={`${FIELD_INPUT} resize-none`}
            />
          </div>

          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className={BTN_GHOST}>
              Cancel
            </button>
            <button type="submit" disabled={isSaving} className={BTN_PRIMARY}>
              {isSaving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
