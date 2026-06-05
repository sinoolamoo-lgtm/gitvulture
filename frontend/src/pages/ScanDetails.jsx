import { useEffect, useMemo, useState, useRef } from "react";
import { useParams, Link } from "react-router-dom";
import { toast } from "sonner";
import {
  ChevronLeft, Download, Bot, GitBranch, FileCode2, KeyRound, Bug, AlertTriangle,
  Sparkles, Shield, Activity, Clock, Hash, ServerCrash, FileText, Terminal, Zap, Crosshair,
} from "lucide-react";
import { getScan, eventSource, reportUrl, dumpUrl, forgeryUrl } from "@/lib/api";

const PHASES = [
  { key: "recon", label: "Reconnaissance" },
  { key: "ref_discovery", label: "Ref Discovery" },
  { key: "object_acquisition", label: "Object Acquisition" },
  { key: "reconstruction", label: "Reconstruction" },
  { key: "secret_hunt", label: "Secret Hunt" },
  { key: "verification", label: "Live Verification" },
  { key: "ai_triage", label: "AI Triage" },
  { key: "done", label: "Done" },
];

function PhaseTimeline({ phaseState }) {
  return (
    <div className="space-y-1" data-testid="phase-timeline">
      {PHASES.map((p) => {
        const st = phaseState[p.key] || "pending";
        return (
          <div key={p.key} className={`phase-step ${st}`} data-testid={`phase-${p.key}`}>
            <span className="w-4 inline-block">
              {st === "running" && "⟳"}
              {st === "done" && "✓"}
              {st === "failed" && "✗"}
              {st === "pending" && "·"}
            </span>
            <span className="tracking-wider uppercase">{p.label}</span>
            <span className="ml-auto text-[10px] opacity-70">{st}</span>
          </div>
        );
      })}
    </div>
  );
}

function StatBlock({ label, value, accent }) {
  return (
    <div className="border border-[#333] p-4">
      <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58]">{label}</div>
      <div className={`font-display text-3xl font-extrabold mt-1 ${accent || "text-white"}`}>
        {value}
      </div>
    </div>
  );
}

function Tabs({ value, onChange, tabs }) {
  return (
    <div className="border-b border-[#1f1f1f] flex flex-wrap" data-testid="tabs-nav">
      {tabs.map((t) => (
        <button
          key={t.value}
          className={`tab ${value === t.value ? "active" : ""}`}
          onClick={() => onChange(t.value)}
          data-testid={`tab-${t.value}`}
        >
          {t.icon} {t.label}
          {typeof t.count === "number" && (
            <span className="ml-2 text-[10px] opacity-70">[{t.count}]</span>
          )}
        </button>
      ))}
    </div>
  );
}

function SeverityPill({ s }) {
  const cls = {
    critical: "pill-critical", high: "pill-high",
    medium: "pill-medium", low: "pill-low",
  }[s] || "pill-info";
  return <span className={`pill ${cls}`}>{s}</span>;
}

function CommitsTab({ commits }) {
  if (!commits?.length) return <div className="font-mono text-[#8B949E] p-6">No commits recovered.</div>;
  return (
    <div className="space-y-2" data-testid="commits-list">
      {commits.map((c, i) => (
        <div key={c.sha} className="panel p-4 fade-up" style={{ animationDelay: `${i * 30}ms` }}>
          <div className="flex items-center gap-3 flex-wrap">
            <Hash size={12} className="text-[#00FF41]" />
            <code className="font-mono text-[12px] text-[#A5D6FF]">{c.sha.slice(0, 12)}</code>
            <span className="font-mono text-[11px] text-[#8B949E]">{c.author}</span>
            <span className="font-mono text-[11px] text-[#484F58] ml-auto">{c.date}</span>
          </div>
          <div className="mt-2 font-mono text-[13px] text-white">{c.message}</div>
          {c.files_changed?.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {c.files_changed.slice(0, 12).map((f) => (
                <span key={f} className="font-mono text-[10px] px-1.5 py-0.5 border border-[#1f1f1f] text-[#8B949E]">
                  {f}
                </span>
              ))}
              {c.files_changed.length > 12 && (
                <span className="font-mono text-[10px] text-[#484F58]">+{c.files_changed.length - 12} more</span>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function SecretsTab({ findings }) {
  if (!findings?.length) return (
    <div className="panel p-10 text-center" data-testid="empty-secrets">
      <Shield size={28} className="text-[#333] mx-auto" />
      <p className="font-mono text-[12px] tracking-[0.2em] uppercase text-[#484F58] mt-3">
        No hard-coded secrets detected
      </p>
    </div>
  );
  const order = ["critical", "high", "medium", "low"];
  const sorted = [...findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  return (
    <div className="overflow-x-auto" data-testid="secrets-table">
      <table className="w-full border-collapse">
        <thead>
          <tr className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58] text-left">
            <th className="px-3 py-2 border-b border-[#1f1f1f]">Severity</th>
            <th className="px-3 py-2 border-b border-[#1f1f1f]">Rule</th>
            <th className="px-3 py-2 border-b border-[#1f1f1f]">Value (redacted)</th>
            <th className="px-3 py-2 border-b border-[#1f1f1f]">File</th>
            <th className="px-3 py-2 border-b border-[#1f1f1f]">Source</th>
            <th className="px-3 py-2 border-b border-[#1f1f1f]">Commit</th>
            <th className="px-3 py-2 border-b border-[#1f1f1f]">Verified</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((f, i) => (
            <tr key={i} className="hover:bg-[#111111] fade-up" data-testid={`finding-row-${i}`}>
              <td className="px-3 py-2 border-b border-[#111111]"><SeverityPill s={f.severity} /></td>
              <td className="px-3 py-2 border-b border-[#111111] font-mono text-[12px] text-white">{f.rule_id}</td>
              <td className="px-3 py-2 border-b border-[#111111] font-mono text-[12px] text-[#A5D6FF]">{f.redacted}</td>
              <td className="px-3 py-2 border-b border-[#111111] font-mono text-[11px] text-[#8B949E] max-w-xs truncate">{f.file_path}</td>
              <td className="px-3 py-2 border-b border-[#111111] font-mono text-[10px] text-[#8B949E] uppercase">{f.source}</td>
              <td className="px-3 py-2 border-b border-[#111111] font-mono text-[11px] text-[#484F58]">{(f.commit_sha || "").slice(0, 10)}</td>
              <td className="px-3 py-2 border-b border-[#111111] font-mono text-[10px]">
                {f.extra?.verified === true && <span className="text-[#00FF41]">✓ live</span>}
                {f.extra?.verified === false && <span className="text-[#FF3333]">✗ invalid</span>}
                {f.extra?.verified === undefined && <span className="text-[#484F58]">—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IndexTab({ entries }) {
  if (!entries?.length) return <div className="font-mono text-[#8B949E] p-6">No index entries recovered.</div>;
  return (
    <div className="overflow-x-auto" data-testid="index-table">
      <table className="w-full border-collapse">
        <thead>
          <tr className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58] text-left">
            <th className="px-3 py-2 border-b border-[#1f1f1f]">#</th>
            <th className="px-3 py-2 border-b border-[#1f1f1f]">Blob SHA</th>
            <th className="px-3 py-2 border-b border-[#1f1f1f]">Mode</th>
            <th className="px-3 py-2 border-b border-[#1f1f1f]">Path</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e, i) => (
            <tr key={i} className="hover:bg-[#111] fade-up">
              <td className="px-3 py-2 border-b border-[#111] font-mono text-[11px] text-[#484F58]">{i + 1}</td>
              <td className="px-3 py-2 border-b border-[#111] font-mono text-[11px] text-[#A5D6FF]">{e.sha1?.slice(0,10)}</td>
              <td className="px-3 py-2 border-b border-[#111] font-mono text-[11px] text-[#8B949E]">{(e.mode||0).toString(8)}</td>
              <td className="px-3 py-2 border-b border-[#111] font-mono text-[12px] text-white break-all">{e.path}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AITab({ ai }) {
  if (!ai) return <div className="font-mono text-[#8B949E] p-6">AI triage was not requested for this scan.</div>;
  if (ai.error) return (
    <div className="panel p-6 border-[#FF3333]">
      <div className="flex items-center gap-2 text-[#FF3333] font-mono uppercase text-xs tracking-widest">
        <AlertTriangle size={14} /> AI error
      </div>
      <pre className="code-block mt-3 text-[#FF3333] whitespace-pre-wrap">{ai.error}{ai.raw ? "\n---\n" + ai.raw : ""}</pre>
    </div>
  );
  return (
    <div className="space-y-5" data-testid="ai-panel">
      <div className="panel p-5 panel-glow border-[#00FF41]/40">
        <div className="flex items-center gap-2 mb-2">
          <Bot size={14} className="text-[#00FF41]" />
          <span className="font-mono text-[11px] tracking-[0.2em] uppercase text-[#00FF41]">Executive Summary</span>
          {typeof ai.risk_score === "number" && (
            <span className="ml-auto font-mono text-xs text-[#8B949E]">
              Risk: <span className="text-white font-bold text-base">{ai.risk_score}</span>/100
            </span>
          )}
        </div>
        <p className="font-mono text-[13px] text-white leading-relaxed">{ai.executive_summary}</p>
        {ai.lab_pattern && ai.lab_pattern !== "none" && (
          <div className="mt-3 inline-block">
            <span className="pill pill-info">Lab pattern: {ai.lab_pattern}</span>
          </div>
        )}
      </div>

      {ai.top_findings?.length > 0 && (
        <div>
          <h3 className="font-display text-lg uppercase tracking-tight font-bold mb-2">Top Findings</h3>
          <div className="space-y-3">
            {ai.top_findings.map((f, i) => (
              <div key={i} className="panel p-4 fade-up">
                <div className="flex items-center gap-3 mb-2">
                  <SeverityPill s={f.severity} />
                  <h4 className="font-mono text-[14px] font-bold text-white">{f.title}</h4>
                </div>
                <p className="text-[13px] text-[#8B949E] mb-3">{f.what_attacker_can_do}</p>
                {f.exploitation_steps?.length > 0 && (
                  <div>
                    <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#00FF41] mb-2">
                      Exploitation steps
                    </div>
                    <ol className="space-y-1.5">
                      {f.exploitation_steps.map((s, j) => (
                        <li key={j} className="flex gap-3 font-mono text-[12px] text-[#A5D6FF]">
                          <span className="text-[#484F58]">{(j + 1).toString().padStart(2, "0")}</span>
                          <span className="break-all">{s}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {ai.next_actions?.length > 0 && (
        <div className="panel p-5">
          <div className="font-mono text-[11px] tracking-[0.2em] uppercase text-[#00FF41] mb-2">Next Actions</div>
          <ul className="space-y-1.5">
            {ai.next_actions.map((a, i) => (
              <li key={i} className="font-mono text-[12px] text-white flex gap-2">
                <span className="text-[#00FF41]">▶</span> {a}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function RebuildTab({ report }) {
  const r = report?.rebuild;
  const recon = report?.recon;
  if (!r && !recon) return <div className="font-mono text-[#8B949E] p-6">No reconstruction data.</div>;
  return (
    <div className="space-y-4" data-testid="rebuild-panel">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatBlock label="Branches" value={(r?.branches || []).length} accent="text-[#00FF41]" />
        <StatBlock label="Tags" value={(r?.tags || []).length} />
        <StatBlock label="Commits" value={(r?.commits || []).length} accent="text-[#A5D6FF]" />
        <StatBlock label="Dangling" value={(r?.dangling_commits?.length || 0) + (r?.dangling_blobs?.length || 0)} accent="text-[#FFBF00]" />
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        <div className="panel p-4">
          <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58] mb-2">Branches</div>
          <div className="space-y-1">
            {(r?.branches || []).map((b) => (
              <div key={b} className="font-mono text-[12px] text-[#00FF41] flex items-center gap-2">
                <GitBranch size={11} /> {b}
              </div>
            ))}
            {(r?.branches || []).length === 0 && <div className="font-mono text-xs text-[#484F58]">—</div>}
          </div>
        </div>
        <div className="panel p-4">
          <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58] mb-2">HEAD &amp; Recon</div>
          <div className="space-y-1 font-mono text-[12px]">
            <div><span className="text-[#484F58]">head:</span> <span className="text-white">{r?.head_branch || "—"}</span></div>
            <div><span className="text-[#484F58]">ref:</span> <span className="text-[#A5D6FF] break-all">{recon?.head_ref || "—"}</span></div>
            <div><span className="text-[#484F58]">server:</span> <span className="text-white">{recon?.server || "—"}</span></div>
            <div><span className="text-[#484F58]">waf:</span> <span className="text-[#FFBF00]">{recon?.waf || "none"}</span></div>
            <div><span className="text-[#484F58]">listing:</span> <span className="text-white">{recon?.has_dir_listing ? "enabled" : "disabled"}</span></div>
          </div>
        </div>
      </div>
      {recon?.config_text && (
        <div className="panel p-4">
          <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58] mb-2">Exposed .git/config</div>
          <pre className="code-block">{recon.config_text}</pre>
        </div>
      )}
      {r?.fsck_errors?.length > 0 && (
        <div className="panel p-4 border-[#FFBF00]/40">
          <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#FFBF00] mb-2">
            fsck warnings ({r.fsck_errors.length})
          </div>
          <pre className="code-block max-h-48 overflow-y-auto">{r.fsck_errors.join("\n")}</pre>
        </div>
      )}
    </div>
  );
}

function EscalationTab({ escalation, scanId }) {
  if (!escalation) return (
    <div className="font-mono text-[#8B949E] p-6">Escalation was not enabled for this scan.</div>
  );
  const stages = escalation.stages || [];
  const strategy = escalation.ai_strategy || {};
  const pivot = escalation.pivot_repo;
  const summary = escalation.summary || {};
  const forgery = escalation.forgery_lab;
  return (
    <div className="space-y-5" data-testid="escalation-panel">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatBlock label="Stages Run" value={summary.stages_run || stages.length} accent="text-[#00FF41]" />
        <StatBlock label="Probes Sent" value={summary.total_probes || 0} accent="text-[#A5D6FF]" />
        <StatBlock label="New Findings" value={summary.new_findings || 0} accent="text-[#FFBF00]" />
        <StatBlock label="Risk" value={(strategy.risk_score ?? "—") + (strategy.risk_score ? "/100" : "")} accent="text-[#FF7A33]" />
      </div>

      {forgery && !forgery.error && (
        <div className="panel p-5 panel-glow border-[#FF3333]/40" data-testid="forgery-lab">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={14} className="text-[#FF3333]" />
            <span className="font-mono text-[11px] tracking-[0.2em] uppercase text-[#FF3333]">
              AI Forgery Lab — Proof of Impact
            </span>
            <a href={forgeryUrl(scanId)} className="btn-ghost ml-auto" data-testid="btn-download-forgery">
              <Download size={12} className="inline mr-1.5 -mt-0.5" /> Download forge.py
            </a>
          </div>
          {forgery.title && (
            <h4 className="font-display text-lg font-bold uppercase tracking-tight text-white mb-2">
              {forgery.title}
            </h4>
          )}
          {forgery.impact && (
            <p className="font-mono text-[13px] text-[#FFBF00] mb-3">⚡ {forgery.impact}</p>
          )}
          {forgery.usage && (
            <div className="mb-3">
              <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#00FF41] mb-1">Usage</div>
              <pre className="code-block">{forgery.usage}</pre>
            </div>
          )}
          {forgery.dependencies?.length > 0 && (
            <div className="mb-3">
              <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#8B949E] mb-1">Dependencies</div>
              <div className="flex flex-wrap gap-1">
                {forgery.dependencies.map((d) => (
                  <span key={d} className="font-mono text-[10px] px-1.5 py-0.5 border border-[#1f1f1f] text-[#A5D6FF]">{d}</span>
                ))}
              </div>
            </div>
          )}
          {forgery.forgery_script && (
            <details className="mt-2">
              <summary className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#FF3333] cursor-pointer">
                view forgery script ({forgery.forgery_script.length} bytes)
              </summary>
              <pre className="code-block mt-2 max-h-96 overflow-y-auto text-[11px]">{forgery.forgery_script}</pre>
            </details>
          )}
          {forgery.next_steps?.length > 0 && (
            <div className="mt-3">
              <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#00FF41] mb-1">Next Steps</div>
              <ul className="space-y-1">
                {forgery.next_steps.map((n, i) => (
                  <li key={i} className="font-mono text-[11px] text-white">▶ {n}</li>
                ))}
              </ul>
            </div>
          )}
          {forgery.legal_note && (
            <div className="mt-3 font-mono text-[10px] text-[#FFBF00] border-t border-[#1f1f1f] pt-2">
              ⚠ {forgery.legal_note}
            </div>
          )}
        </div>
      )}

      {strategy && !strategy.error && (
        <div className="panel p-5 panel-glow border-[#00FF41]/40">
          <div className="flex items-center gap-2 mb-2">
            <Crosshair size={14} className="text-[#00FF41]" />
            <span className="font-mono text-[11px] tracking-[0.2em] uppercase text-[#00FF41]">Final Kill-Chain Verdict</span>
            {strategy.verdict && <span className="ml-auto pill pill-info">{strategy.verdict}</span>}
          </div>
          <p className="font-mono text-[13px] text-white leading-relaxed">{strategy.narrative}</p>
          {strategy.kill_chain?.length > 0 && (
            <div className="mt-4">
              <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#00FF41] mb-2">Kill Chain</div>
              <ol className="space-y-2">
                {strategy.kill_chain.map((s, i) => (
                  <li key={i} className="border-l-2 border-[#00FF41] pl-3 py-1">
                    <div className="font-mono text-[12px] text-white">
                      <span className="text-[#484F58]">#{s.step}</span> {s.action}
                    </div>
                    {s.evidence && <div className="font-mono text-[11px] text-[#8B949E] mt-1">↳ evidence: <span className="text-[#A5D6FF]">{s.evidence}</span></div>}
                    {s.outcome && <div className="font-mono text-[11px] text-[#8B949E] mt-0.5">↳ expected: <span className="text-[#FFBF00]">{s.outcome}</span></div>}
                  </li>
                ))}
              </ol>
            </div>
          )}
          {strategy.top_recommendations?.length > 0 && (
            <div className="mt-4">
              <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#FFBF00] mb-2">Top Recommendations</div>
              <ul className="space-y-1.5">
                {strategy.top_recommendations.map((r, i) => (
                  <li key={i} className="font-mono text-[12px] text-white flex gap-2">
                    <span className="text-[#FFBF00]">▶</span> {r}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {strategy.stop_reasons?.length > 0 && (
            <div className="mt-4">
              <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#FF3333] mb-2">Why Automation Stopped</div>
              <ul className="space-y-1">
                {strategy.stop_reasons.map((r, i) => (
                  <li key={i} className="font-mono text-[11px] text-[#FF7A33] flex gap-2"><span>✗</span> {r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {pivot && (
        <div className="panel p-4">
          <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58] mb-2">Upstream Repo Pivot</div>
          <div className="font-mono text-[12px] space-y-1">
            <div><span className="text-[#484F58]">remote:</span> <span className="text-[#A5D6FF] break-all">{pivot.remote_url}</span></div>
            <div><span className="text-[#484F58]">https candidate:</span> <span className="text-[#00FF41] break-all">{pivot.https_candidate}</span></div>
            <div><span className="text-[#484F58]">public landing:</span> <span className={pivot.public_landing ? "text-[#00FF41]" : "text-[#FF3333]"}>{String(pivot.public_landing)}</span></div>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {stages.map((s, i) => {
          const hits = (s.probes || []).filter((p) => p.status >= 200 && p.status < 300 && p.size > 0);
          return (
            <div key={i} className="panel p-4 fade-up" data-testid={`escalation-stage-${s.level}`}>
              <div className="flex items-center gap-3 flex-wrap">
                <span className="pill pill-info">L{s.level}</span>
                <span className="font-mono text-[13px] text-white font-bold">{s.name}</span>
                <span className="ml-auto font-mono text-[10px] text-[#484F58]">
                  {(s.probes || []).length} probes · {hits.length} hits · {(s.findings || []).length} findings
                </span>
              </div>
              {s.notes?.length > 0 && (
                <ul className="mt-2 space-y-0.5">
                  {s.notes.slice(0, 8).map((n, j) => (
                    <li key={j} className="font-mono text-[11px] text-[#A5D6FF]">↳ {n}</li>
                  ))}
                </ul>
              )}
              {s.artifacts && Object.keys(s.artifacts).length > 0 && (
                <details className="mt-2">
                  <summary className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#FFBF00] cursor-pointer">artifacts</summary>
                  <pre className="code-block mt-2 text-[10px] max-h-60 overflow-y-auto">
                    {JSON.stringify(s.artifacts, null, 2)}
                  </pre>
                </details>
              )}
              {hits.length > 0 && (
                <details className="mt-2">
                  <summary className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#00FF41] cursor-pointer">
                    show {hits.length} successful probes
                  </summary>
                  <div className="mt-2 max-h-72 overflow-y-auto">
                    {hits.slice(0, 80).map((h, j) => (
                      <div key={j} className="font-mono text-[10px] text-[#A5D6FF] py-0.5 border-b border-[#0a0a0a] flex gap-3">
                        <span className="text-[#00FF41]">{h.status}</span>
                        <span className="text-[#484F58]">{h.size}b</span>
                        <span className="text-[#8B949E]">{h.bypass}</span>
                        <span className="break-all">{h.url}</span>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
  if (!escalation) return (
    <div className="font-mono text-[#8B949E] p-6">Escalation was not enabled for this scan.</div>
  );
  const stages = escalation.stages || [];
  const strategy = escalation.ai_strategy || {};
  const pivot = escalation.pivot_repo;
  const summary = escalation.summary || {};
  return (
    <div className="space-y-5" data-testid="escalation-panel">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatBlock label="Stages Run" value={summary.stages_run || stages.length} accent="text-[#00FF41]" />
        <StatBlock label="Probes Sent" value={summary.total_probes || 0} accent="text-[#A5D6FF]" />
        <StatBlock label="New Findings" value={summary.new_findings || 0} accent="text-[#FFBF00]" />
        <StatBlock label="Risk" value={(strategy.risk_score ?? "—") + (strategy.risk_score ? "/100" : "")} accent="text-[#FF7A33]" />
      </div>

      {strategy && !strategy.error && (
        <div className="panel p-5 panel-glow border-[#00FF41]/40">
          <div className="flex items-center gap-2 mb-2">
            <Crosshair size={14} className="text-[#00FF41]" />
            <span className="font-mono text-[11px] tracking-[0.2em] uppercase text-[#00FF41]">Final Kill-Chain Verdict</span>
            {strategy.verdict && <span className="ml-auto pill pill-info">{strategy.verdict}</span>}
          </div>
          <p className="font-mono text-[13px] text-white leading-relaxed">{strategy.narrative}</p>
          {strategy.kill_chain?.length > 0 && (
            <div className="mt-4">
              <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#00FF41] mb-2">Kill Chain</div>
              <ol className="space-y-2">
                {strategy.kill_chain.map((s, i) => (
                  <li key={i} className="border-l-2 border-[#00FF41] pl-3 py-1">
                    <div className="font-mono text-[12px] text-white">
                      <span className="text-[#484F58]">#{s.step}</span> {s.action}
                    </div>
                    {s.evidence && <div className="font-mono text-[11px] text-[#8B949E] mt-1">↳ evidence: <span className="text-[#A5D6FF]">{s.evidence}</span></div>}
                    {s.outcome && <div className="font-mono text-[11px] text-[#8B949E] mt-0.5">↳ expected: <span className="text-[#FFBF00]">{s.outcome}</span></div>}
                  </li>
                ))}
              </ol>
            </div>
          )}
          {strategy.top_recommendations?.length > 0 && (
            <div className="mt-4">
              <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#FFBF00] mb-2">Top Recommendations</div>
              <ul className="space-y-1.5">
                {strategy.top_recommendations.map((r, i) => (
                  <li key={i} className="font-mono text-[12px] text-white flex gap-2">
                    <span className="text-[#FFBF00]">▶</span> {r}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {strategy.stop_reasons?.length > 0 && (
            <div className="mt-4">
              <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#FF3333] mb-2">Why Automation Stopped</div>
              <ul className="space-y-1">
                {strategy.stop_reasons.map((r, i) => (
                  <li key={i} className="font-mono text-[11px] text-[#FF7A33] flex gap-2"><span>✗</span> {r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {pivot && (
        <div className="panel p-4">
          <div className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58] mb-2">Upstream Repo Pivot</div>
          <div className="font-mono text-[12px] space-y-1">
            <div><span className="text-[#484F58]">remote:</span> <span className="text-[#A5D6FF] break-all">{pivot.remote_url}</span></div>
            <div><span className="text-[#484F58]">https candidate:</span> <span className="text-[#00FF41] break-all">{pivot.https_candidate}</span></div>
            <div><span className="text-[#484F58]">public landing:</span> <span className={pivot.public_landing ? "text-[#00FF41]" : "text-[#FF3333]"}>{String(pivot.public_landing)}</span></div>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {stages.map((s, i) => {
          const hits = (s.probes || []).filter((p) => p.status >= 200 && p.status < 300 && p.size > 0);
          return (
            <div key={i} className="panel p-4 fade-up" data-testid={`escalation-stage-${s.level}`}>
              <div className="flex items-center gap-3 flex-wrap">
                <span className="pill pill-info">L{s.level}</span>
                <span className="font-mono text-[13px] text-white font-bold">{s.name}</span>
                <span className="ml-auto font-mono text-[10px] text-[#484F58]">
                  {(s.probes || []).length} probes · {hits.length} hits · {(s.findings || []).length} findings
                </span>
              </div>
              {s.notes?.length > 0 && (
                <ul className="mt-2 space-y-0.5">
                  {s.notes.slice(0, 8).map((n, j) => (
                    <li key={j} className="font-mono text-[11px] text-[#A5D6FF]">↳ {n}</li>
                  ))}
                </ul>
              )}
              {s.artifacts && Object.keys(s.artifacts).length > 0 && (
                <details className="mt-2">
                  <summary className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#FFBF00] cursor-pointer">artifacts</summary>
                  <pre className="code-block mt-2 text-[10px] max-h-40 overflow-y-auto">
                    {JSON.stringify(s.artifacts, null, 2)}
                  </pre>
                </details>
              )}
              {hits.length > 0 && (
                <details className="mt-2">
                  <summary className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#00FF41] cursor-pointer">
                    show {hits.length} successful probes
                  </summary>
                  <div className="mt-2 max-h-72 overflow-y-auto">
                    {hits.slice(0, 80).map((h, j) => (
                      <div key={j} className="font-mono text-[10px] text-[#A5D6FF] py-0.5 border-b border-[#0a0a0a] flex gap-3">
                        <span className="text-[#00FF41]">{h.status}</span>
                        <span className="text-[#484F58]">{h.size}b</span>
                        <span className="text-[#8B949E]">{h.bypass}</span>
                        <span className="break-all">{h.url}</span>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function ScanDetails() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [phaseState, setPhaseState] = useState({});
  const [logs, setLogs] = useState([]);
  const [tab, setTab] = useState("overview");
  const logEnd = useRef(null);

  useEffect(() => {
    let alive = true;
    let es;
    (async () => {
      const s = await getScan(id);
      if (!alive) return;
      setScan(s);
      // Seed phase state from existing report
      if (s?.report?.phase === "done") {
        const ps = {};
        for (const p of PHASES) ps[p.key] = "done";
        setPhaseState(ps);
      }
      if (s.status === "running" || !s.report) {
        es = eventSource(id);
        es.onmessage = (m) => {
          let evt; try { evt = JSON.parse(m.data); } catch { return; }
          if (evt.type === "phase") {
            setPhaseState((ps) => ({ ...ps, [evt.phase]: evt.status }));
            // Whenever a phase finishes, pull a fresh scan snapshot so the UI
            // can show real data (commits, secrets, AI report) as it lands.
            if (evt.status === "done" || evt.phase === "done") {
              getScan(id).then((fresh) => alive && setScan(fresh));
            }
          } else if (evt.type === "log") {
            setLogs((l) => [...l.slice(-200), evt.msg]);
          } else if (evt.type === "finished" || evt.type === "close") {
            getScan(id).then((fresh) => alive && setScan(fresh));
          }
        };
        es.onerror = () => {};
        // Safety net: poll every 3s in case SSE drops behind a proxy
        const poll = setInterval(async () => {
          const fresh = await getScan(id);
          if (!alive) return;
          setScan(fresh);
          if (fresh?.status === "done" || fresh?.status === "failed") {
            clearInterval(poll);
            es?.close();
          }
        }, 3000);
        return () => clearInterval(poll);
      }
    })();
    return () => { alive = false; es?.close(); };
  }, [id]);

  useEffect(() => { logEnd.current?.scrollIntoView({ behavior: "smooth" }); }, [logs]);

  const report = scan?.report;
  const findings = report?.findings || [];
  const commits = report?.rebuild?.commits || [];
  const entries = report?.index_entries || [];

  const tabs = [
    { value: "overview", label: "Overview", icon: <Activity size={12} className="inline mr-1.5 -mt-0.5" /> },
    { value: "commits", label: "Commits", count: commits.length, icon: <Hash size={12} className="inline mr-1.5 -mt-0.5" /> },
    { value: "index", label: "Index", count: entries.length, icon: <FileCode2 size={12} className="inline mr-1.5 -mt-0.5" /> },
    { value: "secrets", label: "Secrets", count: findings.length, icon: <KeyRound size={12} className="inline mr-1.5 -mt-0.5" /> },
    { value: "ai", label: "AI Triage", icon: <Sparkles size={12} className="inline mr-1.5 -mt-0.5" /> },
    { value: "escalation", label: "Escalation", count: (report?.escalation?.stages || []).length, icon: <Zap size={12} className="inline mr-1.5 -mt-0.5" /> },
  ];

  if (!scan) return <div className="font-mono text-[#8B949E]">Loading…</div>;
  return (
    <div className="space-y-6" data-testid="scan-details">
      {/* Header strip */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <Link to="/" className="font-mono text-[11px] text-[#8B949E] hover:text-white flex items-center gap-1" data-testid="back-link">
            <ChevronLeft size={14} /> back
          </Link>
          <h1 className="font-display text-3xl font-extrabold uppercase tracking-tight mt-1 break-all">
            {scan.target_url}
          </h1>
          <div className="font-mono text-[10px] text-[#484F58] mt-1">
            ID {scan.id} · phase {scan.phase} · {scan.status?.toUpperCase()}
            {scan.duration_s && ` · ${scan.duration_s.toFixed(1)}s`}
          </div>
        </div>
        <div className="flex gap-2">
          <a className="btn-ghost" href={reportUrl(id)} target="_blank" rel="noreferrer" data-testid="btn-download-report">
            <Download size={12} className="inline mr-1.5 -mt-0.5" /> Report JSON
          </a>
          <a className="btn-ghost" href={dumpUrl(id)} data-testid="btn-download-dump">
            <Download size={12} className="inline mr-1.5 -mt-0.5" /> .git Dump (tar.gz)
          </a>
        </div>
      </div>

      {/* Status + phase strip */}
      <div className="grid lg:grid-cols-3 gap-4">
        <div className="panel p-5">
          <div className="font-mono text-[11px] tracking-[0.2em] uppercase text-[#484F58] mb-3">Pipeline</div>
          <PhaseTimeline phaseState={phaseState} />
        </div>
        <div className="panel p-5 lg:col-span-2">
          <div className="flex items-center justify-between">
            <div className="font-mono text-[11px] tracking-[0.2em] uppercase text-[#484F58]">Live Log</div>
            <span className="font-mono text-[10px] text-[#484F58]">{logs.length} events</span>
          </div>
          <div className="log-feed mt-2" data-testid="log-feed">
            {logs.length === 0 && <div className="text-[#484F58]">// waiting for events…</div>}
            {logs.map((l, i) => <div key={i}>$ {l}</div>)}
            <div ref={logEnd} />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={tab} onChange={setTab} tabs={tabs} />
      <div className="pt-4">
        {tab === "overview" && <RebuildTab report={report} />}
        {tab === "commits" && <CommitsTab commits={commits} />}
        {tab === "index" && <IndexTab entries={entries} />}
        {tab === "secrets" && <SecretsTab findings={findings} />}
        {tab === "ai" && <AITab ai={report?.ai_report} />}
        {tab === "escalation" && <EscalationTab escalation={report?.escalation} scanId={id} />}
      </div>
    </div>
  );
}
