import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import {
  Crosshair, Zap, Globe, ShieldOff, Bot, KeyRound, Wifi, Cpu,
  Terminal, Settings2, Activity, ChevronRight, Trash2, Eye, AlertTriangle,
} from "lucide-react";
import { createScan, listScans, deleteScan } from "@/lib/api";

const DEFAULTS = {
  target_url: "",
  ai_triage: true,
  verify_secrets: false,
  insecure_ssl: true,
  bypass_403: true,
  ua_rotate: true,
  proxy: "",
  proxy_list: [],
  rate_limit: 30,
  concurrency: 20,
  timeout: 15,
};

function Toggle({ checked, onChange, label, hint, danger, testid }) {
  return (
    <label className="flex items-start gap-3 cursor-pointer group" data-testid={testid}>
      <span
        className={`mt-0.5 inline-flex w-8 h-4 border ${
          checked ? "border-[#00FF41]" : "border-[#333333]"
        } relative transition-all`}
      >
        <span
          className={`absolute top-0 ${checked ? "left-4 bg-[#00FF41]" : "left-0 bg-[#555555]"} w-4 h-[14px] transition-all`}
        />
      </span>
      <span className="flex-1">
        <span className="font-mono text-[12px] font-bold uppercase tracking-wider text-white flex items-center gap-2">
          {label}
          {danger && <AlertTriangle size={12} className="text-[#FFBF00]" />}
        </span>
        {hint && <span className="block text-[11px] text-[#6E7681] mt-0.5 font-mono">{hint}</span>}
      </span>
    </label>
  );
}

function ScanForm({ onLaunched }) {
  const [form, setForm] = useState(DEFAULTS);
  const [submitting, setSubmitting] = useState(false);
  const [advanced, setAdvanced] = useState(false);

  const update = (k, v) => setForm((s) => ({ ...s, [k]: v }));

  const submit = async (e) => {
    e?.preventDefault();
    if (!form.target_url.trim()) {
      toast.error("Target URL required");
      return;
    }
    setSubmitting(true);
    try {
      const payload = { ...form };
      if (payload.proxy?.trim() === "") delete payload.proxy;
      const res = await createScan(payload);
      toast.success("Scan launched: " + res.scan_id.slice(0, 8));
      onLaunched(res.scan_id);
    } catch (err) {
      toast.error("Launch failed: " + (err?.response?.data?.detail || err.message));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={submit} className="panel p-6 panel-glow" data-testid="scan-form">
      <div className="flex items-center gap-3 mb-5">
        <Crosshair size={18} className="text-[#00FF41]" />
        <h2 className="font-display text-lg font-bold tracking-tight uppercase">New Scan</h2>
        <span className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58] ml-auto">
          .git/HEAD probe → reconstruction → triage
        </span>
      </div>

      <label className="block">
        <span className="font-mono text-[11px] tracking-[0.2em] uppercase text-[#8B949E] mb-2 block">
          Target URL
        </span>
        <input
          data-testid="input-target-url"
          className="input-mono"
          placeholder="https://target.example.com"
          value={form.target_url}
          onChange={(e) => update("target_url", e.target.value)}
          autoFocus
        />
      </label>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-4 mt-6">
        <Toggle
          testid="toggle-ai"
          checked={form.ai_triage}
          onChange={(v) => update("ai_triage", v)}
          label="AI Triage (Claude)"
          hint="Smart analysis of findings + exploitation steps"
        />
        <Toggle
          testid="toggle-bypass"
          checked={form.bypass_403}
          onChange={(v) => update("bypass_403", v)}
          label="403 Bypass"
          hint="Path & header tricks against ACLs"
        />
        <Toggle
          testid="toggle-ssl"
          checked={form.insecure_ssl}
          onChange={(v) => update("insecure_ssl", v)}
          label="Insecure SSL"
          hint="Skip cert verification (hostname mismatch)"
        />
        <Toggle
          testid="toggle-ua"
          checked={form.ua_rotate}
          onChange={(v) => update("ua_rotate", v)}
          label="Rotate User-Agent"
          hint="Randomize UA on each request"
        />
        <Toggle
          testid="toggle-verify"
          checked={form.verify_secrets}
          onChange={(v) => update("verify_secrets", v)}
          label="Live Verify Secrets"
          hint="OPT-IN: ping AWS/GitHub/Stripe/etc to test tokens"
          danger
        />
      </div>

      <div className="mt-6 border-t border-[#1f1f1f] pt-4">
        <button
          type="button"
          onClick={() => setAdvanced((v) => !v)}
          className="font-mono text-[11px] tracking-[0.2em] uppercase text-[#8B949E] hover:text-white flex items-center gap-2"
          data-testid="toggle-advanced"
        >
          <Settings2 size={14} /> {advanced ? "Hide" : "Show"} Advanced
        </button>

        {advanced && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
            <label>
              <span className="font-mono text-[11px] tracking-[0.18em] uppercase text-[#8B949E] block mb-1">
                Proxy URL (optional)
              </span>
              <input
                data-testid="input-proxy"
                className="input-mono"
                placeholder="http://127.0.0.1:8080"
                value={form.proxy}
                onChange={(e) => update("proxy", e.target.value)}
              />
            </label>
            <label>
              <span className="font-mono text-[11px] tracking-[0.18em] uppercase text-[#8B949E] block mb-1">
                Rate limit (req/s)
              </span>
              <input
                data-testid="input-rate-limit"
                type="number"
                className="input-mono"
                value={form.rate_limit}
                onChange={(e) => update("rate_limit", Number(e.target.value))}
              />
            </label>
            <label>
              <span className="font-mono text-[11px] tracking-[0.18em] uppercase text-[#8B949E] block mb-1">
                Concurrency
              </span>
              <input
                data-testid="input-concurrency"
                type="number"
                className="input-mono"
                value={form.concurrency}
                onChange={(e) => update("concurrency", Number(e.target.value))}
              />
            </label>
            <label className="md:col-span-3">
              <span className="font-mono text-[11px] tracking-[0.18em] uppercase text-[#8B949E] block mb-1">
                Proxy rotation list (one URL per line)
              </span>
              <textarea
                data-testid="input-proxy-list"
                className="input-mono"
                rows={3}
                placeholder="http://proxy1:port&#10;socks5://proxy2:port"
                value={form.proxy_list.join("\n")}
                onChange={(e) =>
                  update(
                    "proxy_list",
                    e.target.value.split("\n").map((s) => s.trim()).filter(Boolean),
                  )
                }
              />
            </label>
          </div>
        )}
      </div>

      <div className="flex items-center gap-3 mt-6">
        <button type="submit" className="btn-primary" disabled={submitting} data-testid="btn-launch">
          {submitting ? "Launching…" : "▶  Launch Scan"}
        </button>
        <span className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58]">
          Authorized testing only
        </span>
      </div>
    </form>
  );
}

function ScanRow({ scan, onDelete }) {
  const created = new Date(scan.created_at).toLocaleString();
  const status = scan.status;
  const sevColor = {
    pending: "pill-info",
    running: "pill-medium",
    done: "pill-low",
    failed: "pill-critical",
  }[status] || "pill-info";

  return (
    <Link
      to={`/scan/${scan.id}`}
      className="panel grid grid-cols-12 gap-4 px-4 py-3 items-center hover:border-white transition-colors fade-up"
      data-testid={`row-scan-${scan.id}`}
    >
      <div className="col-span-5 font-mono text-[13px] text-white break-all">{scan.target_url}</div>
      <div className="col-span-3 font-mono text-[11px] text-[#8B949E]">{created}</div>
      <div className="col-span-2 font-mono text-[10px] text-[#A5D6FF]">
        {(scan.phase || "—").toUpperCase()}
      </div>
      <div className="col-span-1">
        <span className={`pill ${sevColor}`}>{status}</span>
      </div>
      <div className="col-span-1 flex justify-end gap-1" onClick={(e) => e.preventDefault()}>
        <button
          className="btn-ghost !px-2 !py-1"
          title="Open"
          onClick={(e) => { e.preventDefault(); window.location.href = `/scan/${scan.id}`; }}
          data-testid={`btn-open-${scan.id}`}
        >
          <Eye size={12} />
        </button>
        <button
          className="btn-ghost !px-2 !py-1"
          title="Delete"
          onClick={async (e) => {
            e.preventDefault();
            if (!window.confirm("Delete this scan?")) return;
            try { await deleteScan(scan.id); onDelete(scan.id); toast.success("Deleted"); }
            catch { toast.error("Failed"); }
          }}
          data-testid={`btn-delete-${scan.id}`}
        >
          <Trash2 size={12} />
        </button>
      </div>
    </Link>
  );
}

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const refresh = async () => {
    try {
      setScans(await listScans());
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { refresh(); const t = setInterval(refresh, 4000); return () => clearInterval(t); }, []);

  return (
    <div className="space-y-8" data-testid="dashboard">
      {/* Hero */}
      <section className="grid lg:grid-cols-5 gap-8 items-start">
        <div className="lg:col-span-3">
          <div className="font-mono text-[10px] tracking-[0.3em] uppercase text-[#484F58] mb-3">
            // offensive recon framework
          </div>
          <h1 className="font-display text-5xl lg:text-6xl font-extrabold uppercase tracking-tighter leading-[0.95]">
            Hunt every byte<br />
            of an exposed <span className="text-[#00FF41] terminal-cursor">.git</span>
          </h1>
          <p className="text-[#8B949E] text-base leading-relaxed mt-6 max-w-2xl">
            GitVulture downloads, reconstructs and forensically analyzes leaked Git directories — even
            when directory listing is disabled, the server returns 403, or the certificate is broken.
            Built on the strongest ideas from <code className="font-mono text-[#A5D6FF]">git-dumper</code>,
            <code className="font-mono text-[#A5D6FF]"> GitTools</code>,
            <code className="font-mono text-[#A5D6FF]"> GitHacker</code>,
            <code className="font-mono text-[#A5D6FF]"> Gitleaks</code> and
            <code className="font-mono text-[#A5D6FF]"> TruffleHog</code> — without duplication, plus AI triage.
          </p>

          <div className="grid grid-cols-3 gap-3 mt-6" data-testid="feature-strip">
            {[
              { icon: <Globe size={14} />, label: "12-source ref discovery" },
              { icon: <ShieldOff size={14} />, label: "403 / SSL bypass" },
              { icon: <KeyRound size={14} />, label: "Secret scanning" },
              { icon: <Bot size={14} />, label: "Claude AI triage" },
              { icon: <Wifi size={14} />, label: "Rotating proxy" },
              { icon: <Cpu size={14} />, label: "Reflog resurrection" },
            ].map((f) => (
              <div key={f.label} className="border border-[#333333] p-3 flex items-center gap-2">
                <span className="text-[#00FF41]">{f.icon}</span>
                <span className="font-mono text-[11px] uppercase tracking-wider">{f.label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="lg:col-span-2">
          <ScanForm onLaunched={(id) => { refresh(); navigate(`/scan/${id}`); }} />
        </div>
      </section>

      {/* Scans list */}
      <section data-testid="scan-list">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-display text-2xl font-bold tracking-tight uppercase">
            ● Scan History
          </h2>
          <span className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58]">
            {scans.length} total
          </span>
        </div>

        {loading ? (
          <div className="panel p-8 text-center font-mono text-[#8B949E]">Loading…</div>
        ) : scans.length === 0 ? (
          <div className="panel p-10 text-center" data-testid="empty-state">
            <Terminal size={32} className="mx-auto text-[#333333]" />
            <p className="font-mono text-[12px] tracking-[0.2em] uppercase text-[#484F58] mt-4">
              No scans yet · drop a target above to begin
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            <div className="grid grid-cols-12 gap-4 px-4 py-2 font-mono text-[10px] tracking-[0.2em] uppercase text-[#484F58] border-b border-[#1f1f1f]">
              <div className="col-span-5">Target</div>
              <div className="col-span-3">Started</div>
              <div className="col-span-2">Phase</div>
              <div className="col-span-1">Status</div>
              <div className="col-span-1 text-right">Actions</div>
            </div>
            {scans.map((s) => (
              <ScanRow key={s.id} scan={s} onDelete={refresh} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
