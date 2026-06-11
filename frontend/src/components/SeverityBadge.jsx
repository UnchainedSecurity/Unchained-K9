import React from 'react';

export function SeverityBadge({ severity }) {
  const styles = {
    Critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
    High: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    Medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
    Low: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
    Info: 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30',
    Unknown: 'bg-slate-500/20 text-slate-400 border border-slate-500/30',
    None: 'bg-slate-500/20 text-slate-400 border border-slate-500/30'
  };
  return (
    <span className={`px-2.5 py-1 text-xs font-semibold rounded-full ${styles[severity] || styles.Unknown}`}>
      {severity}
    </span>
  );
}
