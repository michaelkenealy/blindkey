import { useState } from "react";
import { Lock, LockOpen, Eye, EyeOff, Plus, X, Copy, Shield, FolderOpen, Folder, Key, Activity, AlertTriangle, Check, RefreshCw, Settings } from "lucide-react";

// ─── Design Tokens (from Design System v1.0) ───
const tokens = {
  bg: { root: "#0a0a0a", surface: "#111111", elevated: "#1a1a1a", input: "#141414" },
  border: { default: "#222222", hover: "#333333", focus: "#555555" },
  text: { primary: "#fafafa", secondary: "#a1a1a1", tertiary: "#666666", inverse: "#0a0a0a" },
  accent: { base: "#00d672", hover: "#00b860", subtle: "rgba(0,214,114,0.08)", border: "rgba(0,214,114,0.25)" },
  status: {
    locked: "#ef4444", lockedSubtle: "rgba(239,68,68,0.08)",
    warning: "#f59e0b", warningSubtle: "rgba(245,158,11,0.08)",
    info: "#3b82f6", infoSubtle: "rgba(59,130,246,0.08)",
  },
};

// ─── Badge Component ───
type BadgeColor = "accent" | "red" | "yellow" | "blue" | "gray";

const Badge = ({ children, color = "accent", className = "" }: { children: React.ReactNode; color?: BadgeColor; className?: string }) => {
  const colors: Record<BadgeColor, { bg: string; text: string; border: string }> = {
    accent: { bg: tokens.accent.subtle, text: tokens.accent.base, border: tokens.accent.border },
    red: { bg: tokens.status.lockedSubtle, text: tokens.status.locked, border: "rgba(239,68,68,0.25)" },
    yellow: { bg: tokens.status.warningSubtle, text: tokens.status.warning, border: "rgba(245,158,11,0.25)" },
    blue: { bg: tokens.status.infoSubtle, text: tokens.status.info, border: "rgba(59,130,246,0.25)" },
    gray: { bg: "rgba(255,255,255,0.04)", text: tokens.text.secondary, border: tokens.border.default },
  };
  const c = colors[color];
  return (
    <span className={className} style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 500,
      letterSpacing: "0.04em", textTransform: "uppercase",
      background: c.bg, color: c.text, border: `1px solid ${c.border}`,
    }}>{children}</span>
  );
};

// ─── Secrets Page ───
interface SecretEntry {
  id: number;
  name: string;
  value: string;
  service: string;
  domains: string[];
  ttl: number;
  visible: boolean;
  created: string;
}

const SecretsPage = () => {
  const [secrets, setSecrets] = useState<SecretEntry[]>([
    { id: 1, name: "STRIPE_PROD_KEY", value: "sk_live_51Hx...a8Ks", service: "Stripe", domains: ["api.stripe.com"], ttl: 30, visible: false, created: "2 days ago" },
    { id: 2, name: "GITHUB_PAT", value: "ghp_xK29...mNp4", service: "GitHub", domains: ["api.github.com"], ttl: 60, visible: false, created: "5 days ago" },
    { id: 3, name: "OPENAI_API_KEY", value: "sk-proj-9x...wR2f", service: "OpenAI", domains: ["api.openai.com"], ttl: 30, visible: false, created: "1 week ago" },
    { id: 4, name: "AWS_SECRET_KEY", value: "wJalrXUtnF...QMZK", service: "AWS", domains: ["*.amazonaws.com"], ttl: 15, visible: false, created: "1 week ago" },
  ]);
  const [newKey, setNewKey] = useState("");
  const [newVal, setNewVal] = useState("");
  const [newDomain, setNewDomain] = useState("");
  const [copied, setCopied] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const addSecret = () => {
    if (!newKey || !newVal) return;
    setSecrets([...secrets, {
      id: Date.now(), name: newKey, value: newVal, service: "Custom",
      domains: newDomain ? [newDomain] : [], ttl: 30, visible: false, created: "just now"
    }]);
    setNewKey(""); setNewVal(""); setNewDomain("");
  };

  const removeSecret = (id: number) => setSecrets(secrets.filter(s => s.id !== id));
  const toggleVisible = (id: number) => setSecrets(secrets.map(s => s.id === id ? { ...s, visible: !s.visible } : s));
  const copyRef = (name: string) => { setCopied(name); setTimeout(() => setCopied(null), 2000); };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 32 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 600, color: tokens.text.primary, margin: 0 }}>Secrets</h1>
          <p style={{ fontSize: 14, color: tokens.text.secondary, margin: "6px 0 0" }}>
            API keys and tokens your agent can use without seeing. Injected at runtime via vault references.
          </p>
        </div>
      </div>

      {/* Secret Rows */}
      <div style={{ border: `1px solid ${tokens.border.default}`, borderRadius: 8, overflow: "hidden" }}>
        {/* Header */}
        <div style={{
          display: "grid", gridTemplateColumns: "200px 1fr 140px 100px 48px",
          padding: "10px 16px", background: tokens.bg.surface,
          borderBottom: `1px solid ${tokens.border.default}`,
          fontSize: 11, fontWeight: 500, color: tokens.text.tertiary,
          letterSpacing: "0.04em", textTransform: "uppercase",
        }}>
          <span>Name</span><span>Vault Reference</span><span>Domains</span><span>TTL</span><span></span>
        </div>

        {secrets.map((s, i) => (
          <div key={s.id}>
            <div
              onClick={() => setExpandedId(expandedId === s.id ? null : s.id)}
              style={{
                display: "grid", gridTemplateColumns: "200px 1fr 140px 100px 48px",
                padding: "12px 16px", alignItems: "center",
                borderBottom: i < secrets.length - 1 || expandedId === s.id ? `1px solid ${tokens.border.default}` : "none",
                cursor: "pointer",
                background: expandedId === s.id ? tokens.bg.elevated : "transparent",
                transition: "background 150ms ease",
              }}
              onMouseEnter={e => { if (expandedId !== s.id) (e.currentTarget as HTMLDivElement).style.background = tokens.bg.elevated; }}
              onMouseLeave={e => { if (expandedId !== s.id) (e.currentTarget as HTMLDivElement).style.background = "transparent"; }}
            >
              <span style={{ fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 13, color: tokens.text.primary, fontWeight: 500 }}>
                {s.name}
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 12, color: tokens.text.tertiary }}>
                  bk://{s.name.toLowerCase().replace(/_/g, "-")}
                </span>
                <button onClick={(e) => { e.stopPropagation(); copyRef(s.name); }} style={{
                  background: "none", border: "none", cursor: "pointer", padding: 2,
                  color: copied === s.name ? tokens.accent.base : tokens.text.tertiary,
                  transition: "color 150ms",
                }}>
                  {copied === s.name ? <Check size={14} /> : <Copy size={14} />}
                </button>
              </div>
              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                {s.domains.map((d, di) => (
                  <Badge key={di} color="gray">{d}</Badge>
                ))}
              </div>
              <span style={{ fontSize: 12, color: tokens.text.secondary }}>{s.ttl}m</span>
              <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                <button onClick={(e) => { e.stopPropagation(); removeSecret(s.id); }} style={{
                  background: "none", border: "none", cursor: "pointer", padding: 4, borderRadius: 4,
                  color: tokens.text.tertiary, transition: "color 150ms",
                }}
                  onMouseEnter={e => (e.currentTarget as HTMLButtonElement).style.color = tokens.status.locked}
                  onMouseLeave={e => (e.currentTarget as HTMLButtonElement).style.color = tokens.text.tertiary}
                >
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* Expanded Detail */}
            {expandedId === s.id && (
              <div style={{
                padding: "16px 16px 16px 32px", background: tokens.bg.surface,
                borderBottom: `1px solid ${tokens.border.default}`,
                display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16,
              }}>
                <div>
                  <label style={{ fontSize: 11, color: tokens.text.tertiary, textTransform: "uppercase", letterSpacing: "0.04em" }}>Value</label>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
                    <div style={{
                      flex: 1, padding: "8px 12px", borderRadius: 6,
                      background: tokens.bg.input, border: `1px solid ${tokens.border.default}`,
                      fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 13, color: tokens.text.primary,
                    }}>
                      {s.visible ? s.value : "\u2022".repeat(24)}
                    </div>
                    <button onClick={() => toggleVisible(s.id)} style={{
                      background: "none", border: "none", cursor: "pointer", padding: 4,
                      color: tokens.text.tertiary,
                    }}>
                      {s.visible ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: tokens.text.tertiary, textTransform: "uppercase", letterSpacing: "0.04em" }}>Service</label>
                  <div style={{ marginTop: 6, fontSize: 14, color: tokens.text.primary }}>{s.service}</div>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: tokens.text.tertiary, textTransform: "uppercase", letterSpacing: "0.04em" }}>Created</label>
                  <div style={{ marginTop: 6, fontSize: 13, color: tokens.text.secondary }}>{s.created}</div>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: tokens.text.tertiary, textTransform: "uppercase", letterSpacing: "0.04em" }}>Injection TTL</label>
                  <div style={{ marginTop: 6, fontSize: 13, color: tokens.text.secondary }}>{s.ttl} minutes</div>
                </div>
                <div style={{ gridColumn: "1 / -1", display: "flex", gap: 8, paddingTop: 8 }}>
                  <button style={{
                    display: "flex", alignItems: "center", gap: 6, padding: "6px 12px",
                    background: "none", border: `1px solid ${tokens.border.default}`,
                    borderRadius: 6, color: tokens.text.secondary, fontSize: 13, cursor: "pointer",
                    transition: "all 150ms",
                  }}
                    onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = tokens.border.hover; (e.currentTarget as HTMLButtonElement).style.color = tokens.text.primary; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = tokens.border.default; (e.currentTarget as HTMLButtonElement).style.color = tokens.text.secondary; }}
                  >
                    <RefreshCw size={14} /> Rotate
                  </button>
                  <button style={{
                    display: "flex", alignItems: "center", gap: 6, padding: "6px 12px",
                    background: "none", border: `1px solid ${tokens.border.default}`,
                    borderRadius: 6, color: tokens.text.secondary, fontSize: 13, cursor: "pointer",
                    transition: "all 150ms",
                  }}
                    onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = tokens.border.hover; (e.currentTarget as HTMLButtonElement).style.color = tokens.text.primary; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = tokens.border.default; (e.currentTarget as HTMLButtonElement).style.color = tokens.text.secondary; }}
                  >
                    <Settings size={14} /> Edit Policy
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}

        {/* Add New Row */}
        <div style={{
          display: "grid", gridTemplateColumns: "200px 1fr 140px auto",
          padding: "8px 16px", gap: 8, alignItems: "center",
        }}>
          <input
            value={newKey} onChange={e => setNewKey(e.target.value)}
            placeholder="SECRET_NAME"
            style={{
              padding: "8px 12px", borderRadius: 6, border: `1px solid ${tokens.border.default}`,
              background: tokens.bg.input, color: tokens.text.primary,
              fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 13, outline: "none",
              transition: "border-color 150ms",
            }}
            onFocus={e => (e.target as HTMLInputElement).style.borderColor = tokens.border.focus}
            onBlur={e => (e.target as HTMLInputElement).style.borderColor = tokens.border.default}
          />
          <input
            value={newVal} onChange={e => setNewVal(e.target.value)}
            placeholder="Secret value..."
            type="password"
            style={{
              padding: "8px 12px", borderRadius: 6, border: `1px solid ${tokens.border.default}`,
              background: tokens.bg.input, color: tokens.text.primary, fontSize: 13, outline: "none",
              transition: "border-color 150ms",
            }}
            onFocus={e => (e.target as HTMLInputElement).style.borderColor = tokens.border.focus}
            onBlur={e => (e.target as HTMLInputElement).style.borderColor = tokens.border.default}
          />
          <input
            value={newDomain} onChange={e => setNewDomain(e.target.value)}
            placeholder="api.domain.com"
            style={{
              padding: "8px 12px", borderRadius: 6, border: `1px solid ${tokens.border.default}`,
              background: tokens.bg.input, color: tokens.text.secondary, fontSize: 12, outline: "none",
              transition: "border-color 150ms",
            }}
            onFocus={e => (e.target as HTMLInputElement).style.borderColor = tokens.border.focus}
            onBlur={e => (e.target as HTMLInputElement).style.borderColor = tokens.border.default}
          />
          <button onClick={addSecret} style={{
            display: "flex", alignItems: "center", gap: 6, padding: "8px 16px",
            background: newKey && newVal ? tokens.accent.base : tokens.bg.elevated,
            color: newKey && newVal ? tokens.text.inverse : tokens.text.tertiary,
            border: "none", borderRadius: 6, fontSize: 13, fontWeight: 500,
            cursor: newKey && newVal ? "pointer" : "default",
            transition: "all 150ms",
          }}>
            <Plus size={14} /> Add
          </button>
        </div>
      </div>
    </div>
  );
};

// ─── Filesystem Page ───
interface FsGrant {
  id: number;
  path: string;
  permission: string;
  recursive: boolean;
  approval: boolean;
}

const FilesystemPage = () => {
  const [grants, setGrants] = useState<FsGrant[]>([
    { id: 1, path: "/project/src", permission: "read", recursive: true, approval: false },
    { id: 2, path: "/project/output", permission: "write", recursive: true, approval: false },
    { id: 3, path: "/project/deploy", permission: "write", recursive: false, approval: true },
  ]);

  const blocked = [
    { path: "~/.ssh", reason: "SSH keys" },
    { path: "~/.aws", reason: "AWS credentials" },
    { path: "~/.env", reason: "Environment file" },
    { path: "~/.git/config", reason: "Git credentials" },
  ];

  const tree = [
    { path: "/project", depth: 0, type: "dir", sensitive: false },
    { path: "/project/src", depth: 1, type: "dir", sensitive: false },
    { path: "/project/output", depth: 1, type: "dir", sensitive: false },
    { path: "/project/deploy", depth: 1, type: "dir", sensitive: false },
    { path: "/project/.env", depth: 1, type: "file", sensitive: true },
    { path: "/documents", depth: 0, type: "dir", sensitive: false },
    { path: "/documents/contracts", depth: 1, type: "dir", sensitive: false },
    { path: "/.ssh", depth: 0, type: "dir", sensitive: true },
    { path: "/.aws", depth: 0, type: "dir", sensitive: true },
  ];

  const getGrant = (path: string) => grants.find(g => g.path === path);

  const toggleGrant = (path: string) => {
    const existing = getGrant(path);
    if (existing) {
      setGrants(grants.filter(g => g.path !== path));
    } else {
      setGrants([...grants, { id: Date.now(), path, permission: "read", recursive: true, approval: false }]);
    }
  };

  const updatePermission = (path: string, perm: string) => {
    setGrants(grants.map(g => g.path === path ? { ...g, permission: perm } : g));
  };

  return (
    <div>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: tokens.text.primary, margin: 0 }}>Filesystem</h1>
        <p style={{ fontSize: 14, color: tokens.text.secondary, margin: "6px 0 0" }}>
          Control which directories your agent can access. Everything is locked by default.
        </p>
      </div>

      {/* Default Deny Banner */}
      <div style={{
        display: "flex", alignItems: "center", gap: 12, padding: "12px 16px",
        background: "rgba(0,214,114,0.04)", border: `1px solid ${tokens.accent.border}`,
        borderRadius: 8, marginBottom: 24,
      }}>
        <Shield size={18} style={{ color: tokens.accent.base, flexShrink: 0 }} />
        <span style={{ fontSize: 13, color: tokens.text.secondary }}>
          <strong style={{ color: tokens.text.primary }}>Default-deny active.</strong> Your agent cannot see or access any path unless explicitly unlocked below.
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 24 }}>
        {/* File Tree */}
        <div style={{ border: `1px solid ${tokens.border.default}`, borderRadius: 8, overflow: "hidden" }}>
          <div style={{
            padding: "10px 16px", background: tokens.bg.surface,
            borderBottom: `1px solid ${tokens.border.default}`,
            fontSize: 11, fontWeight: 500, color: tokens.text.tertiary,
            letterSpacing: "0.04em", textTransform: "uppercase",
          }}>
            Directory Tree
          </div>

          {tree.map((item, i) => {
            const grant = getGrant(item.path);
            const sensitive = item.sensitive;
            const isGranted = !!grant;

            return (
              <div key={item.path} style={{
                display: "flex", alignItems: "center", gap: 8,
                padding: "10px 16px", paddingLeft: 16 + item.depth * 24,
                borderBottom: i < tree.length - 1 ? `1px solid ${tokens.border.default}` : "none",
                background: isGranted ? tokens.accent.subtle : "transparent",
                transition: "background 150ms",
              }}>
                {/* Icon */}
                {isGranted ? (
                  <LockOpen size={15} style={{ color: tokens.accent.base, flexShrink: 0 }} />
                ) : sensitive ? (
                  <Lock size={15} style={{ color: tokens.status.locked, flexShrink: 0 }} />
                ) : (
                  <Folder size={15} style={{ color: tokens.text.tertiary, flexShrink: 0 }} />
                )}

                {/* Path */}
                <span style={{
                  flex: 1, fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 13,
                  color: isGranted ? tokens.text.primary : sensitive ? tokens.text.tertiary : tokens.text.secondary,
                }}>
                  {item.path}
                </span>

                {/* Sensitive Warning */}
                {sensitive && !isGranted && (
                  <Badge color="red">
                    <AlertTriangle size={10} /> blocked
                  </Badge>
                )}

                {/* Permission Dropdown */}
                {isGranted && grant && (
                  <select
                    value={grant.permission}
                    onChange={e => updatePermission(item.path, e.target.value)}
                    style={{
                      padding: "3px 8px", borderRadius: 4, fontSize: 11, fontWeight: 500,
                      background: tokens.bg.input, color: tokens.accent.base,
                      border: `1px solid ${tokens.accent.border}`,
                      outline: "none", cursor: "pointer", textTransform: "uppercase",
                      letterSpacing: "0.04em",
                    }}
                  >
                    <option value="read">Read</option>
                    <option value="write">Read + Write</option>
                    <option value="approval">Approval Req</option>
                  </select>
                )}

                {/* Toggle Button */}
                {!sensitive && (
                  <button onClick={() => toggleGrant(item.path)} style={{
                    padding: "4px 10px", borderRadius: 4, fontSize: 11,
                    background: isGranted ? "rgba(239,68,68,0.08)" : "rgba(255,255,255,0.04)",
                    color: isGranted ? tokens.status.locked : tokens.text.tertiary,
                    border: `1px solid ${isGranted ? "rgba(239,68,68,0.2)" : tokens.border.default}`,
                    cursor: "pointer", transition: "all 150ms", fontWeight: 500,
                  }}>
                    {isGranted ? "Revoke" : "Unlock"}
                  </button>
                )}
              </div>
            );
          })}
        </div>

        {/* Sidebar: Active Grants Summary */}
        <div>
          <div style={{
            border: `1px solid ${tokens.border.default}`, borderRadius: 8,
            overflow: "hidden",
          }}>
            <div style={{
              padding: "10px 16px", background: tokens.bg.surface,
              borderBottom: `1px solid ${tokens.border.default}`,
              fontSize: 11, fontWeight: 500, color: tokens.text.tertiary,
              letterSpacing: "0.04em", textTransform: "uppercase",
              display: "flex", justifyContent: "space-between",
            }}>
              <span>Active Grants</span>
              <Badge color="accent">{grants.length}</Badge>
            </div>

            {grants.map((g, i) => (
              <div key={g.id} style={{
                padding: "10px 16px", display: "flex", alignItems: "center", gap: 8,
                borderBottom: i < grants.length - 1 ? `1px solid ${tokens.border.default}` : "none",
              }}>
                <LockOpen size={14} style={{ color: tokens.accent.base }} />
                <span style={{ flex: 1, fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 12, color: tokens.text.primary }}>
                  {g.path}
                </span>
                <Badge color={g.permission === "approval" ? "yellow" : g.permission === "write" ? "blue" : "accent"}>
                  {g.permission === "approval" ? "approval" : g.permission}
                </Badge>
              </div>
            ))}
          </div>

          {/* Always Blocked */}
          <div style={{
            border: `1px solid ${tokens.border.default}`, borderRadius: 8,
            overflow: "hidden", marginTop: 16,
          }}>
            <div style={{
              padding: "10px 16px", background: tokens.bg.surface,
              borderBottom: `1px solid ${tokens.border.default}`,
              fontSize: 11, fontWeight: 500, color: tokens.text.tertiary,
              letterSpacing: "0.04em", textTransform: "uppercase",
            }}>
              Always Blocked
            </div>
            {blocked.map((b, i) => (
              <div key={b.path} style={{
                padding: "8px 16px", display: "flex", alignItems: "center", gap: 8,
                borderBottom: i < blocked.length - 1 ? `1px solid ${tokens.border.default}` : "none",
              }}>
                <Lock size={14} style={{ color: tokens.status.locked }} />
                <span style={{ flex: 1, fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 12, color: tokens.text.tertiary }}>
                  {b.path}
                </span>
                <span style={{ fontSize: 11, color: tokens.text.tertiary }}>{b.reason}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── Sessions Page ───
const SessionsPage = () => {
  const sessions = [
    { id: "bk_7kx9m2", agent: "Claude via MCP", purpose: "Refund processing", secrets: 2, fs: 3, status: "active", created: "12 min ago", expires: "48 min" },
    { id: "bk_p3n8w1", agent: "Custom GPT", purpose: "Code review", secrets: 1, fs: 2, status: "active", created: "2 hours ago", expires: "22 min" },
    { id: "bk_r5t2q8", agent: "OpenClaw Worker", purpose: "Deploy pipeline", secrets: 3, fs: 1, status: "expired", created: "Yesterday", expires: "\u2014" },
    { id: "bk_m1k4j6", agent: "Claude Code", purpose: "Feature development", secrets: 1, fs: 4, status: "revoked", created: "2 days ago", expires: "\u2014" },
  ];

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 32 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 600, color: tokens.text.primary, margin: 0 }}>Sessions</h1>
          <p style={{ fontSize: 14, color: tokens.text.secondary, margin: "6px 0 0" }}>
            Active and past agent sessions. Each session scopes which secrets and folders an agent can access.
          </p>
        </div>
        <button style={{
          display: "flex", alignItems: "center", gap: 6, padding: "8px 16px",
          background: tokens.accent.base, color: tokens.text.inverse,
          border: "none", borderRadius: 6, fontSize: 13, fontWeight: 500, cursor: "pointer",
        }}>
          <Plus size={14} /> New Session
        </button>
      </div>

      <div style={{ border: `1px solid ${tokens.border.default}`, borderRadius: 8, overflow: "hidden" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "120px 140px 1fr 80px 80px 80px 80px",
          padding: "10px 16px", background: tokens.bg.surface,
          borderBottom: `1px solid ${tokens.border.default}`,
          fontSize: 11, fontWeight: 500, color: tokens.text.tertiary,
          letterSpacing: "0.04em", textTransform: "uppercase",
        }}>
          <span>Session</span><span>Agent</span><span>Purpose</span>
          <span>Secrets</span><span>Folders</span><span>Status</span><span>TTL</span>
        </div>

        {sessions.map((s, i) => (
          <div key={s.id} style={{
            display: "grid", gridTemplateColumns: "120px 140px 1fr 80px 80px 80px 80px",
            padding: "12px 16px", alignItems: "center",
            borderBottom: i < sessions.length - 1 ? `1px solid ${tokens.border.default}` : "none",
            transition: "background 150ms", cursor: "pointer",
          }}
            onMouseEnter={e => (e.currentTarget as HTMLDivElement).style.background = tokens.bg.elevated}
            onMouseLeave={e => (e.currentTarget as HTMLDivElement).style.background = "transparent"}
          >
            <span style={{ fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 12, color: tokens.text.secondary }}>
              {s.id}
            </span>
            <span style={{ fontSize: 13, color: tokens.text.primary }}>{s.agent}</span>
            <span style={{ fontSize: 13, color: tokens.text.secondary }}>{s.purpose}</span>
            <span style={{ fontSize: 13, color: tokens.text.secondary }}>{s.secrets}</span>
            <span style={{ fontSize: 13, color: tokens.text.secondary }}>{s.fs}</span>
            <Badge color={s.status === "active" ? "accent" : s.status === "revoked" ? "red" : "gray"}>
              {s.status === "active" && "\u25CF "}{s.status}
            </Badge>
            <span style={{ fontSize: 12, color: s.expires === "\u2014" ? tokens.text.tertiary : tokens.text.secondary }}>
              {s.expires}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ─── Audit Page ───
const AuditPage = () => {
  const entries = [
    { time: "14:32:05", session: "bk_7kx9m2", action: "API Request", target: "POST /v1/charges", secret: "STRIPE_PROD_KEY", status: "allowed", detail: "Charge $20.00 USD" },
    { time: "14:31:58", session: "bk_7kx9m2", action: "File Read", target: "/project/src/handler.ts", secret: "\u2014", status: "allowed", detail: "2.4 KB" },
    { time: "14:31:42", session: "bk_p3n8w1", action: "API Request", target: "GET /repos/acme/app", secret: "GITHUB_PAT", status: "allowed", detail: "Repo metadata" },
    { time: "14:31:30", session: "bk_7kx9m2", action: "File Read", target: "/.ssh/id_rsa", secret: "\u2014", status: "blocked", detail: "No filesystem grant" },
    { time: "14:30:15", session: "bk_7kx9m2", action: "API Request", target: "GET /v1/account", secret: "STRIPE_PROD_KEY", status: "blocked", detail: "Endpoint not in allowlist" },
    { time: "14:29:50", session: "bk_p3n8w1", action: "File Write", target: "/project/output/review.md", secret: "\u2014", status: "allowed", detail: "1.1 KB written" },
  ];

  return (
    <div>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: tokens.text.primary, margin: 0 }}>Audit Log</h1>
        <p style={{ fontSize: 14, color: tokens.text.secondary, margin: "6px 0 0" }}>
          Every action your agents take, logged immutably. API calls, file operations, and policy enforcements.
        </p>
      </div>

      <div style={{ border: `1px solid ${tokens.border.default}`, borderRadius: 8, overflow: "hidden" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "80px 100px 100px 200px 140px 80px 1fr",
          padding: "10px 16px", background: tokens.bg.surface,
          borderBottom: `1px solid ${tokens.border.default}`,
          fontSize: 11, fontWeight: 500, color: tokens.text.tertiary,
          letterSpacing: "0.04em", textTransform: "uppercase",
        }}>
          <span>Time</span><span>Session</span><span>Action</span><span>Target</span>
          <span>Secret</span><span>Status</span><span>Detail</span>
        </div>

        {entries.map((e, i) => (
          <div key={i} style={{
            display: "grid", gridTemplateColumns: "80px 100px 100px 200px 140px 80px 1fr",
            padding: "10px 16px", alignItems: "center",
            borderBottom: i < entries.length - 1 ? `1px solid ${tokens.border.default}` : "none",
            transition: "background 150ms",
          }}
            onMouseEnter={ev => (ev.currentTarget as HTMLDivElement).style.background = tokens.bg.elevated}
            onMouseLeave={ev => (ev.currentTarget as HTMLDivElement).style.background = "transparent"}
          >
            <span style={{ fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 12, color: tokens.text.tertiary }}>
              {e.time}
            </span>
            <span style={{ fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 12, color: tokens.text.secondary }}>
              {e.session}
            </span>
            <Badge color={e.action.includes("File") ? "blue" : "gray"}>{e.action}</Badge>
            <span style={{ fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 12, color: tokens.text.primary, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {e.target}
            </span>
            <span style={{ fontFamily: "'Geist Mono', 'SF Mono', monospace", fontSize: 12, color: tokens.text.secondary }}>
              {e.secret}
            </span>
            <Badge color={e.status === "allowed" ? "accent" : "red"}>{e.status}</Badge>
            <span style={{ fontSize: 12, color: tokens.text.secondary }}>{e.detail}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ─── Main Dashboard ───
type PageId = "secrets" | "filesystem" | "sessions" | "audit";

export default function BlindKeyDashboard() {
  const [activePage, setActivePage] = useState<PageId>("secrets");
  const [sidebarHover, setSidebarHover] = useState<string | null>(null);

  const nav: { id: PageId; label: string; icon: typeof Key }[] = [
    { id: "secrets", label: "Secrets", icon: Key },
    { id: "filesystem", label: "Filesystem", icon: FolderOpen },
    { id: "sessions", label: "Sessions", icon: Shield },
    { id: "audit", label: "Audit Log", icon: Activity },
  ];

  const pages: Record<PageId, React.ReactNode> = {
    secrets: <SecretsPage />,
    filesystem: <FilesystemPage />,
    sessions: <SessionsPage />,
    audit: <AuditPage />,
  };

  return (
    <div style={{
      display: "flex", minHeight: "100vh", background: tokens.bg.root,
      fontFamily: "'Geist', -apple-system, BlinkMacSystemFont, sans-serif",
      color: tokens.text.primary,
    }}>
      {/* ─── Sidebar ─── */}
      <div style={{
        width: 240, borderRight: `1px solid ${tokens.border.default}`,
        display: "flex", flexDirection: "column", padding: "0",
        position: "fixed", top: 0, left: 0, bottom: 0,
        background: tokens.bg.root, zIndex: 10,
      }}>
        {/* Logo */}
        <div style={{
          padding: "20px 20px 16px", display: "flex", alignItems: "center", gap: 10,
          borderBottom: `1px solid ${tokens.border.default}`,
        }}>
          <div style={{
            width: 28, height: 28, borderRadius: 6,
            background: `linear-gradient(135deg, ${tokens.accent.base}, #00a85a)`,
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <Shield size={16} style={{ color: tokens.text.inverse }} />
          </div>
          <span style={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.01em" }}>BlindKey</span>
        </div>

        {/* Nav */}
        <nav style={{ padding: "12px 8px", flex: 1 }}>
          {nav.map(item => {
            const Icon = item.icon;
            const active = activePage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActivePage(item.id)}
                onMouseEnter={() => setSidebarHover(item.id)}
                onMouseLeave={() => setSidebarHover(null)}
                style={{
                  width: "100%", display: "flex", alignItems: "center", gap: 10,
                  padding: "8px 12px", marginBottom: 2, borderRadius: 6,
                  background: active ? "rgba(255,255,255,0.06)" : sidebarHover === item.id ? "rgba(255,255,255,0.03)" : "transparent",
                  border: "none", cursor: "pointer",
                  color: active ? tokens.text.primary : tokens.text.secondary,
                  fontSize: 13, fontWeight: active ? 500 : 400,
                  transition: "all 150ms", textAlign: "left",
                  position: "relative",
                }}
              >
                {active && <div style={{
                  position: "absolute", left: -8, top: "50%", transform: "translateY(-50%)",
                  width: 3, height: 16, borderRadius: 2, background: tokens.accent.base,
                }} />}
                <Icon size={17} style={{ opacity: active ? 1 : 0.5 }} />
                {item.label}
                {item.id === "audit" && (
                  <span style={{
                    marginLeft: "auto", fontSize: 10, padding: "1px 6px",
                    borderRadius: 9999, background: "rgba(255,255,255,0.06)",
                    color: tokens.text.tertiary,
                  }}>6</span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Bottom */}
        <div style={{ padding: "12px 20px", borderTop: `1px solid ${tokens.border.default}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{
              width: 28, height: 28, borderRadius: 9999,
              background: "rgba(255,255,255,0.08)",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 12, fontWeight: 500, color: tokens.text.secondary,
            }}>S</div>
            <div>
              <div style={{ fontSize: 13, color: tokens.text.primary }}>Sam</div>
              <div style={{ fontSize: 11, color: tokens.text.tertiary }}>Pro Plan</div>
            </div>
          </div>
        </div>
      </div>

      {/* ─── Main Content ─── */}
      <div style={{ marginLeft: 240, flex: 1, padding: "32px 40px", maxWidth: 1200 }}>
        {pages[activePage]}
      </div>
    </div>
  );
}
