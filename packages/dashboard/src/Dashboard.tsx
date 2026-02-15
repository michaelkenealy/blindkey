import { useState, useEffect, useCallback } from "react";
import { Lock, LockOpen, Plus, X, Copy, Shield, FolderOpen, Folder, Key, Activity, AlertTriangle, Check, RefreshCw, ChevronRight, Zap, LogOut, Loader, FileWarning, Download, Filter, Eye, EyeOff, Trash2 } from "lucide-react";
import {
  isLoggedIn, clearToken, login, register, verifyTotp,
  fetchSecrets, createSecret, deleteSecret, rotateSecret,
  setupTotp, confirmTotp, disableTotp, getTotpStatus,
  fetchGrants, createGrant, deleteGrant,
  type SecretMetadata, type GrantMetadata, ApiError,
} from "./api";
import {
  fetchAuditLog, fetchAuditCount,
  fetchPolicies, addPolicy, removePolicy, togglePolicy,
  type AuditRow, type PolicyRow,
} from "./api/vault-client";

// ─── Design Tokens ───
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

const Badge = ({ children, color = "accent" }: { children: React.ReactNode; color?: BadgeColor }) => {
  const colors: Record<BadgeColor, { bg: string; text: string; border: string }> = {
    accent: { bg: tokens.accent.subtle, text: tokens.accent.base, border: tokens.accent.border },
    red: { bg: tokens.status.lockedSubtle, text: tokens.status.locked, border: "rgba(239,68,68,0.25)" },
    yellow: { bg: tokens.status.warningSubtle, text: tokens.status.warning, border: "rgba(245,158,11,0.25)" },
    blue: { bg: tokens.status.infoSubtle, text: tokens.status.info, border: "rgba(59,130,246,0.25)" },
    gray: { bg: "rgba(255,255,255,0.04)", text: tokens.text.secondary, border: tokens.border.default },
  };
  const c = colors[color];
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 500,
      letterSpacing: "0.04em", textTransform: "uppercase",
      background: c.bg, color: c.text, border: `1px solid ${c.border}`,
    }}>{children}</span>
  );
};

// ─── Shared State Types ───
// SecretEntry is now SecretMetadata from the API (see api.ts).
// No plaintext value is ever stored client-side after creation.

interface FsGrant {
  id: string;
  path: string;
  permission: string;
  recursive: boolean;
  approval: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// SIMPLE MODE - Minimal UI for non-experts
// Just API Keys and Folder Access
// ═══════════════════════════════════════════════════════════════════════════

interface SimpleDashboardProps {
  secrets: SecretMetadata[];
  refreshSecrets: () => Promise<void>;
  loading: boolean;
  grants: FsGrant[];
  setGrants: React.Dispatch<React.SetStateAction<FsGrant[]>>;
  onSwitchToExpert: () => void;
  onLogout: () => void;
}

const SimpleDashboard = ({ secrets, refreshSecrets, loading, grants, setGrants, onSwitchToExpert, onLogout }: SimpleDashboardProps) => {
  const [newKey, setNewKey] = useState("");
  const [newVal, setNewVal] = useState("");
  const [newPath, setNewPath] = useState("");
  const [copied, setCopied] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const addSecret = async () => {
    if (!newKey || !newVal) return;
    setSaving(true);
    setError(null);
    try {
      await createSecret({
        name: newKey.toUpperCase(),
        service: "Custom",
        secret_type: "api_key",
        plaintext_value: newVal,
      });
      setNewKey(""); setNewVal("");
      await refreshSecrets();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to save key");
    } finally {
      setSaving(false);
    }
  };

  const removeSecret = async (id: string) => {
    setError(null);
    try {
      await deleteSecret(id);
      await refreshSecrets();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to delete key");
    }
  };

  const addFolder = async () => {
    if (!newPath) return;
    const path = newPath.startsWith("/") ? newPath : `/${newPath}`;
    if (grants.find(g => g.path === path)) return;
    setError(null);
    try {
      const grant = await createGrant({ path, permissions: ["read"], recursive: true });
      setGrants([...grants, { id: grant.id, path: grant.path, permission: "read", recursive: grant.recursive, approval: grant.requires_approval }]);
      setNewPath("");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to unlock folder");
    }
  };

  const removeFolder = async (id: string) => {
    setError(null);
    try {
      await deleteGrant(id);
      setGrants(grants.filter(g => g.id !== id));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to revoke folder");
    }
  };

  const copyRef = (vaultRef: string, name: string) => {
    navigator.clipboard.writeText(vaultRef);
    setCopied(name);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div style={{ maxWidth: 640, margin: "0 auto", padding: "40px 24px" }}>
      {/* Header */}
      <div style={{ textAlign: "center", marginBottom: 48 }}>
        <div style={{
          width: 56, height: 56, borderRadius: 16, margin: "0 auto 16px",
          background: `linear-gradient(135deg, ${tokens.accent.base}, #00a85a)`,
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <Shield size={28} style={{ color: tokens.text.inverse }} />
        </div>
        <h1 style={{ fontSize: 28, fontWeight: 600, color: tokens.text.primary, margin: "0 0 8px" }}>
          BlindKey
        </h1>
        <p style={{ fontSize: 15, color: tokens.text.secondary, margin: 0 }}>
          Secure your API keys. Control folder access.
        </p>
      </div>

      {error && (
        <div style={{
          padding: "10px 14px", marginBottom: 16, borderRadius: 8,
          background: tokens.status.lockedSubtle, color: tokens.status.locked,
          border: `1px solid rgba(239,68,68,0.25)`, fontSize: 13,
          display: "flex", alignItems: "center", gap: 8,
        }}>
          <AlertTriangle size={14} /> {error}
          <button onClick={() => setError(null)} style={{
            marginLeft: "auto", background: "none", border: "none",
            color: tokens.status.locked, cursor: "pointer", padding: 2,
          }}><X size={14} /></button>
        </div>
      )}

      {/* ─── API Keys Section ─── */}
      <div style={{ marginBottom: 40 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
          <Key size={18} style={{ color: tokens.accent.base }} />
          <h2 style={{ fontSize: 16, fontWeight: 600, color: tokens.text.primary, margin: 0 }}>
            API Keys
          </h2>
          <Badge color="accent">{secrets.length}</Badge>
        </div>

        {/* Existing Keys */}
        <div style={{
          border: `1px solid ${tokens.border.default}`, borderRadius: 12,
          overflow: "hidden", marginBottom: 12,
        }}>
          {loading ? (
            <div style={{ padding: 24, textAlign: "center", color: tokens.text.tertiary, fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
              <Loader size={16} style={{ animation: "spin 1s linear infinite" }} /> Loading...
            </div>
          ) : secrets.length === 0 ? (
            <div style={{ padding: 24, textAlign: "center", color: tokens.text.tertiary, fontSize: 14 }}>
              No API keys yet. Add one below.
            </div>
          ) : (
            secrets.map((s, i) => (
              <div key={s.id} style={{
                display: "flex", alignItems: "center", gap: 12, padding: "14px 16px",
                borderBottom: i < secrets.length - 1 ? `1px solid ${tokens.border.default}` : "none",
              }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 8, background: tokens.bg.elevated,
                  display: "flex", alignItems: "center", justifyContent: "center",
                }}>
                  <Key size={16} style={{ color: tokens.accent.base }} />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{
                    fontFamily: "'Geist Mono', monospace", fontSize: 14,
                    fontWeight: 500, color: tokens.text.primary,
                  }}>
                    {s.name}
                  </div>
                  <div style={{ fontSize: 12, color: tokens.text.tertiary, marginTop: 2 }}>
                    {s.service} · Added {new Date(s.created_at).toLocaleDateString()}
                  </div>
                </div>
                <button onClick={() => copyRef(s.vault_ref, s.name)} style={{
                  background: "none", border: "none", cursor: "pointer", padding: 8,
                  color: copied === s.name ? tokens.accent.base : tokens.text.tertiary,
                  transition: "color 150ms",
                }}>
                  {copied === s.name ? <Check size={16} /> : <Copy size={16} />}
                </button>
                <button onClick={() => removeSecret(s.id)} style={{
                  background: "none", border: "none", cursor: "pointer", padding: 8,
                  color: tokens.text.tertiary, transition: "color 150ms",
                }}
                  onMouseEnter={e => (e.currentTarget as HTMLButtonElement).style.color = tokens.status.locked}
                  onMouseLeave={e => (e.currentTarget as HTMLButtonElement).style.color = tokens.text.tertiary}
                >
                  <X size={16} />
                </button>
              </div>
            ))
          )}
        </div>

        {/* Add New Key */}
        <div style={{
          display: "flex", gap: 8, padding: 4, background: tokens.bg.surface,
          borderRadius: 12, border: `1px solid ${tokens.border.default}`,
        }}>
          <input
            value={newKey}
            onChange={e => setNewKey(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "_"))}
            placeholder="KEY_NAME"
            style={{
              flex: "0 0 140px", padding: "12px 14px", borderRadius: 8,
              background: tokens.bg.input, border: "none", outline: "none",
              fontFamily: "'Geist Mono', monospace", fontSize: 13,
              color: tokens.text.primary,
            }}
          />
          <input
            value={newVal}
            onChange={e => setNewVal(e.target.value)}
            placeholder="Paste your API key here..."
            type="password"
            style={{
              flex: 1, padding: "12px 14px", borderRadius: 8,
              background: tokens.bg.input, border: "none", outline: "none",
              fontSize: 13, color: tokens.text.primary,
            }}
          />
          <button onClick={addSecret} disabled={!newKey || !newVal || saving} style={{
            display: "flex", alignItems: "center", gap: 6, padding: "0 20px",
            background: newKey && newVal && !saving ? tokens.accent.base : tokens.bg.elevated,
            color: newKey && newVal && !saving ? tokens.text.inverse : tokens.text.tertiary,
            border: "none", borderRadius: 8, fontSize: 14, fontWeight: 500,
            cursor: newKey && newVal && !saving ? "pointer" : "default",
            transition: "all 150ms",
          }}>
            {saving ? <><Loader size={16} style={{ animation: "spin 1s linear infinite" }} /> Saving...</> : <><Plus size={16} /> Add</>}
          </button>
        </div>
      </div>

      {/* ─── Folder Access Section ─── */}
      <div style={{ marginBottom: 40 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
          <FolderOpen size={18} style={{ color: tokens.accent.base }} />
          <h2 style={{ fontSize: 16, fontWeight: 600, color: tokens.text.primary, margin: 0 }}>
            Folder Access
          </h2>
          <Badge color="accent">{grants.length}</Badge>
        </div>

        {/* Info Banner */}
        <div style={{
          display: "flex", alignItems: "center", gap: 10, padding: "10px 14px",
          background: tokens.accent.subtle, borderRadius: 8, marginBottom: 12,
          border: `1px solid ${tokens.accent.border}`,
        }}>
          <Shield size={16} style={{ color: tokens.accent.base, flexShrink: 0 }} />
          <span style={{ fontSize: 13, color: tokens.text.secondary }}>
            Agents can only access folders you unlock. Everything else is blocked.
          </span>
        </div>

        {/* Granted Folders */}
        <div style={{
          border: `1px solid ${tokens.border.default}`, borderRadius: 12,
          overflow: "hidden", marginBottom: 12,
        }}>
          {grants.length === 0 ? (
            <div style={{ padding: 24, textAlign: "center", color: tokens.text.tertiary, fontSize: 14 }}>
              No folders unlocked. Add a path below.
            </div>
          ) : (
            grants.map((g, i) => (
              <div key={g.id} style={{
                display: "flex", alignItems: "center", gap: 12, padding: "14px 16px",
                borderBottom: i < grants.length - 1 ? `1px solid ${tokens.border.default}` : "none",
              }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 8, background: tokens.accent.subtle,
                  display: "flex", alignItems: "center", justifyContent: "center",
                }}>
                  <LockOpen size={16} style={{ color: tokens.accent.base }} />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{
                    fontFamily: "'Geist Mono', monospace", fontSize: 14,
                    fontWeight: 500, color: tokens.text.primary,
                  }}>
                    {g.path}
                  </div>
                  <div style={{ fontSize: 12, color: tokens.text.tertiary, marginTop: 2 }}>
                    Read access · Includes subfolders
                  </div>
                </div>
                <button onClick={() => removeFolder(g.id)} style={{
                  padding: "6px 12px", borderRadius: 6, fontSize: 12, fontWeight: 500,
                  background: tokens.status.lockedSubtle, color: tokens.status.locked,
                  border: `1px solid rgba(239,68,68,0.2)`, cursor: "pointer",
                  transition: "all 150ms",
                }}>
                  Revoke
                </button>
              </div>
            ))
          )}
        </div>

        {/* Add New Folder */}
        <div style={{
          display: "flex", gap: 8, padding: 4, background: tokens.bg.surface,
          borderRadius: 12, border: `1px solid ${tokens.border.default}`,
        }}>
          <input
            value={newPath}
            onChange={e => setNewPath(e.target.value)}
            placeholder="/path/to/folder"
            style={{
              flex: 1, padding: "12px 14px", borderRadius: 8,
              background: tokens.bg.input, border: "none", outline: "none",
              fontFamily: "'Geist Mono', monospace", fontSize: 13,
              color: tokens.text.primary,
            }}
            onKeyDown={e => e.key === "Enter" && addFolder()}
          />
          <button onClick={addFolder} disabled={!newPath} style={{
            display: "flex", alignItems: "center", gap: 6, padding: "0 20px",
            background: newPath ? tokens.accent.base : tokens.bg.elevated,
            color: newPath ? tokens.text.inverse : tokens.text.tertiary,
            border: "none", borderRadius: 8, fontSize: 14, fontWeight: 500,
            cursor: newPath ? "pointer" : "default",
            transition: "all 150ms",
          }}>
            <LockOpen size={16} /> Unlock
          </button>
        </div>
      </div>

      {/* ─── Switch to Expert Mode ─── */}
      <div style={{ textAlign: "center", paddingTop: 16 }}>
        <button onClick={onSwitchToExpert} style={{
          display: "inline-flex", alignItems: "center", gap: 8,
          padding: "10px 20px", background: "none",
          border: `1px solid ${tokens.border.default}`,
          borderRadius: 8, color: tokens.text.secondary, fontSize: 13,
          cursor: "pointer", transition: "all 150ms",
        }}
          onMouseEnter={e => {
            (e.currentTarget as HTMLButtonElement).style.borderColor = tokens.border.hover;
            (e.currentTarget as HTMLButtonElement).style.color = tokens.text.primary;
          }}
          onMouseLeave={e => {
            (e.currentTarget as HTMLButtonElement).style.borderColor = tokens.border.default;
            (e.currentTarget as HTMLButtonElement).style.color = tokens.text.secondary;
          }}
        >
          <Zap size={14} /> Switch to Expert Mode
          <ChevronRight size={14} />
        </button>
        <p style={{ fontSize: 12, color: tokens.text.tertiary, marginTop: 8 }}>
          Sessions, audit logs, policies, and advanced settings
        </p>
      </div>

      {/* Logout */}
      <div style={{ textAlign: "center", paddingTop: 24 }}>
        <button onClick={onLogout} style={{
          display: "inline-flex", alignItems: "center", gap: 6,
          padding: "8px 16px", background: "none", border: "none",
          color: tokens.text.tertiary, fontSize: 12, cursor: "pointer",
        }}>
          <LogOut size={14} /> Log out
        </button>
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════
// EXPERT MODE PAGES (original full-featured pages)
// ═══════════════════════════════════════════════════════════════════════════

interface SecretsPageProps {
  secrets: SecretMetadata[];
  refreshSecrets: () => Promise<void>;
  loading: boolean;
}

const SecretsPage = ({ secrets, refreshSecrets, loading }: SecretsPageProps) => {
  const [newKey, setNewKey] = useState("");
  const [newVal, setNewVal] = useState("");
  const [newDomain, setNewDomain] = useState("");
  const [copied, setCopied] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rotateId, setRotateId] = useState<string | null>(null);
  const [rotateVal, setRotateVal] = useState("");

  const addSecret = async () => {
    if (!newKey || !newVal) return;
    setSaving(true);
    setError(null);
    try {
      await createSecret({
        name: newKey,
        service: "Custom",
        secret_type: "api_key",
        plaintext_value: newVal,
        allowed_domains: newDomain ? [newDomain] : undefined,
      });
      setNewKey(""); setNewVal(""); setNewDomain("");
      await refreshSecrets();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to save secret");
    } finally {
      setSaving(false);
    }
  };

  const removeSecretHandler = async (id: string) => {
    setError(null);
    try {
      await deleteSecret(id);
      await refreshSecrets();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to delete secret");
    }
  };

  const handleRotate = async (id: string) => {
    if (!rotateVal) return;
    setError(null);
    try {
      await rotateSecret(id, rotateVal);
      setRotateId(null);
      setRotateVal("");
      await refreshSecrets();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to rotate secret");
    }
  };

  const copyRef = (vaultRef: string, name: string) => {
    navigator.clipboard.writeText(vaultRef);
    setCopied(name);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: tokens.text.primary, margin: 0 }}>Secrets</h1>
        <p style={{ fontSize: 14, color: tokens.text.secondary, margin: "6px 0 0" }}>
          API keys and tokens with domain restrictions and injection TTLs.
        </p>
      </div>

      {error && (
        <div style={{
          padding: "10px 14px", marginBottom: 16, borderRadius: 8,
          background: tokens.status.lockedSubtle, color: tokens.status.locked,
          border: `1px solid rgba(239,68,68,0.25)`, fontSize: 13,
          display: "flex", alignItems: "center", gap: 8,
        }}>
          <AlertTriangle size={14} /> {error}
          <button onClick={() => setError(null)} style={{
            marginLeft: "auto", background: "none", border: "none",
            color: tokens.status.locked, cursor: "pointer", padding: 2,
          }}><X size={14} /></button>
        </div>
      )}

      <div style={{ border: `1px solid ${tokens.border.default}`, borderRadius: 8, overflow: "hidden" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "200px 1fr 140px 100px 48px",
          padding: "10px 16px", background: tokens.bg.surface,
          borderBottom: `1px solid ${tokens.border.default}`,
          fontSize: 11, fontWeight: 500, color: tokens.text.tertiary,
          letterSpacing: "0.04em", textTransform: "uppercase",
        }}>
          <span>Name</span><span>Vault Reference</span><span>Domains</span><span>TTL</span><span></span>
        </div>

        {loading ? (
          <div style={{ padding: 24, textAlign: "center", color: tokens.text.tertiary, fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
            <Loader size={16} style={{ animation: "spin 1s linear infinite" }} /> Loading...
          </div>
        ) : secrets.map((s, i) => (
          <div key={s.id}>
            <div
              onClick={() => setExpandedId(expandedId === s.id ? null : s.id)}
              style={{
                display: "grid", gridTemplateColumns: "200px 1fr 140px 100px 48px",
                padding: "12px 16px", alignItems: "center",
                borderBottom: i < secrets.length - 1 || expandedId === s.id ? `1px solid ${tokens.border.default}` : "none",
                cursor: "pointer",
                background: expandedId === s.id ? tokens.bg.elevated : "transparent",
                transition: "background 150ms",
              }}
              onMouseEnter={e => { if (expandedId !== s.id) (e.currentTarget as HTMLDivElement).style.background = tokens.bg.elevated; }}
              onMouseLeave={e => { if (expandedId !== s.id) (e.currentTarget as HTMLDivElement).style.background = "transparent"; }}
            >
              <span style={{ fontFamily: "'Geist Mono', monospace", fontSize: 13, color: tokens.text.primary, fontWeight: 500 }}>
                {s.name}
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontFamily: "'Geist Mono', monospace", fontSize: 12, color: tokens.text.tertiary }}>
                  {s.vault_ref}
                </span>
                <button onClick={(e) => { e.stopPropagation(); copyRef(s.vault_ref, s.name); }} style={{
                  background: "none", border: "none", cursor: "pointer", padding: 2,
                  color: copied === s.name ? tokens.accent.base : tokens.text.tertiary,
                }}>
                  {copied === s.name ? <Check size={14} /> : <Copy size={14} />}
                </button>
              </div>
              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                {(s.allowed_domains ?? []).map((d, di) => <Badge key={di} color="gray">{d}</Badge>)}
              </div>
              <span style={{ fontSize: 12, color: tokens.text.secondary }}>{Math.round(s.injection_ttl_seconds / 60)}m</span>
              <button onClick={(e) => { e.stopPropagation(); removeSecretHandler(s.id); }} style={{
                background: "none", border: "none", cursor: "pointer", padding: 4, color: tokens.text.tertiary,
              }}>
                <X size={16} />
              </button>
            </div>

            {expandedId === s.id && (
              <div style={{
                padding: "16px 16px 16px 32px", background: tokens.bg.surface,
                borderBottom: `1px solid ${tokens.border.default}`,
                display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16,
              }}>
                <div>
                  <label style={{ fontSize: 11, color: tokens.text.tertiary, textTransform: "uppercase", letterSpacing: "0.04em" }}>Service</label>
                  <div style={{ marginTop: 6, fontSize: 14, color: tokens.text.primary }}>{s.service}</div>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: tokens.text.tertiary, textTransform: "uppercase", letterSpacing: "0.04em" }}>Type</label>
                  <div style={{ marginTop: 6, fontSize: 14, color: tokens.text.primary }}>{s.secret_type}</div>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: tokens.text.tertiary, textTransform: "uppercase", letterSpacing: "0.04em" }}>Created</label>
                  <div style={{ marginTop: 6, fontSize: 14, color: tokens.text.primary }}>{new Date(s.created_at).toLocaleString()}</div>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: tokens.text.tertiary, textTransform: "uppercase", letterSpacing: "0.04em" }}>Last Rotated</label>
                  <div style={{ marginTop: 6, fontSize: 14, color: tokens.text.primary }}>{new Date(s.rotated_at).toLocaleString()}</div>
                </div>
                <div style={{ gridColumn: "1 / -1", display: "flex", gap: 8, paddingTop: 8, alignItems: "center" }}>
                  {rotateId === s.id ? (
                    <>
                      <input
                        value={rotateVal}
                        onChange={e => setRotateVal(e.target.value)}
                        placeholder="New secret value..."
                        type="password"
                        style={{
                          flex: 1, padding: "6px 12px", borderRadius: 6,
                          border: `1px solid ${tokens.border.default}`,
                          background: tokens.bg.input, color: tokens.text.primary, fontSize: 13, outline: "none",
                        }}
                      />
                      <button onClick={() => handleRotate(s.id)} disabled={!rotateVal} style={{
                        display: "flex", alignItems: "center", gap: 6, padding: "6px 12px",
                        background: rotateVal ? tokens.accent.base : tokens.bg.elevated,
                        color: rotateVal ? tokens.text.inverse : tokens.text.tertiary,
                        border: "none", borderRadius: 6, fontSize: 13, fontWeight: 500, cursor: rotateVal ? "pointer" : "default",
                      }}>
                        <Check size={14} /> Confirm
                      </button>
                      <button onClick={() => { setRotateId(null); setRotateVal(""); }} style={{
                        display: "flex", alignItems: "center", gap: 6, padding: "6px 12px",
                        background: "none", border: `1px solid ${tokens.border.default}`,
                        borderRadius: 6, color: tokens.text.secondary, fontSize: 13, cursor: "pointer",
                      }}>
                        <X size={14} /> Cancel
                      </button>
                    </>
                  ) : (
                    <button onClick={() => setRotateId(s.id)} style={{
                      display: "flex", alignItems: "center", gap: 6, padding: "6px 12px",
                      background: "none", border: `1px solid ${tokens.border.default}`,
                      borderRadius: 6, color: tokens.text.secondary, fontSize: 13, cursor: "pointer",
                    }}>
                      <RefreshCw size={14} /> Rotate
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}

        <div style={{ display: "grid", gridTemplateColumns: "200px 1fr 140px auto", padding: "8px 16px", gap: 8, alignItems: "center" }}>
          <input value={newKey} onChange={e => setNewKey(e.target.value)} placeholder="SECRET_NAME" style={{
            padding: "8px 12px", borderRadius: 6, border: `1px solid ${tokens.border.default}`,
            background: tokens.bg.input, color: tokens.text.primary, fontFamily: "'Geist Mono', monospace", fontSize: 13, outline: "none",
          }} />
          <input value={newVal} onChange={e => setNewVal(e.target.value)} placeholder="Secret value..." type="password" style={{
            padding: "8px 12px", borderRadius: 6, border: `1px solid ${tokens.border.default}`,
            background: tokens.bg.input, color: tokens.text.primary, fontSize: 13, outline: "none",
          }} />
          <input value={newDomain} onChange={e => setNewDomain(e.target.value)} placeholder="api.domain.com" style={{
            padding: "8px 12px", borderRadius: 6, border: `1px solid ${tokens.border.default}`,
            background: tokens.bg.input, color: tokens.text.secondary, fontSize: 12, outline: "none",
          }} />
          <button onClick={addSecret} disabled={saving} style={{
            display: "flex", alignItems: "center", gap: 6, padding: "8px 16px",
            background: newKey && newVal && !saving ? tokens.accent.base : tokens.bg.elevated,
            color: newKey && newVal && !saving ? tokens.text.inverse : tokens.text.tertiary,
            border: "none", borderRadius: 6, fontSize: 13, fontWeight: 500,
            cursor: newKey && newVal && !saving ? "pointer" : "default",
          }}>
            {saving ? <><Loader size={14} style={{ animation: "spin 1s linear infinite" }} /> Saving...</> : <><Plus size={14} /> Add</>}
          </button>
        </div>
      </div>
    </div>
  );
};

interface FilesystemPageProps {
  grants: FsGrant[];
  setGrants: React.Dispatch<React.SetStateAction<FsGrant[]>>;
}

const FilesystemPage = ({ grants, setGrants }: FilesystemPageProps) => {
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
    { path: "/.ssh", depth: 0, type: "dir", sensitive: true },
    { path: "/.aws", depth: 0, type: "dir", sensitive: true },
  ];

  const [fsError, setFsError] = useState<string | null>(null);

  const getGrant = (path: string) => grants.find(g => g.path === path);
  const toggleGrant = async (path: string) => {
    const existing = getGrant(path);
    setFsError(null);
    try {
      if (existing) {
        await deleteGrant(existing.id);
        setGrants(grants.filter(g => g.path !== path));
      } else {
        const grant = await createGrant({ path, permissions: ["read"], recursive: true });
        setGrants([...grants, { id: grant.id, path: grant.path, permission: "read", recursive: grant.recursive, approval: grant.requires_approval }]);
      }
    } catch (e) {
      setFsError(e instanceof ApiError ? e.message : "Failed to update grant");
    }
  };
  const updatePermission = async (path: string, perm: string) => {
    const existing = getGrant(path);
    if (!existing) return;
    setFsError(null);
    try {
      // Delete and re-create with new permissions
      await deleteGrant(existing.id);
      const permArray = perm === "write" ? ["read", "write"] : perm === "approval" ? ["read"] : ["read"];
      const grant = await createGrant({ path, permissions: permArray, recursive: true, requires_approval: perm === "approval" });
      setGrants(grants.map(g => g.path === path ? { id: grant.id, path: grant.path, permission: perm, recursive: grant.recursive, approval: grant.requires_approval } : g));
    } catch (e) {
      setFsError(e instanceof ApiError ? e.message : "Failed to update permission");
    }
  };

  return (
    <div>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: tokens.text.primary, margin: 0 }}>Filesystem</h1>
        <p style={{ fontSize: 14, color: tokens.text.secondary, margin: "6px 0 0" }}>
          Control directory access with granular permissions.
        </p>
      </div>

      <div style={{
        display: "flex", alignItems: "center", gap: 12, padding: "12px 16px",
        background: tokens.accent.subtle, border: `1px solid ${tokens.accent.border}`,
        borderRadius: 8, marginBottom: 24,
      }}>
        <Shield size={18} style={{ color: tokens.accent.base }} />
        <span style={{ fontSize: 13, color: tokens.text.secondary }}>
          <strong style={{ color: tokens.text.primary }}>Default-deny active.</strong> Agents cannot access any path unless unlocked.
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 24 }}>
        <div style={{ border: `1px solid ${tokens.border.default}`, borderRadius: 8, overflow: "hidden" }}>
          <div style={{
            padding: "10px 16px", background: tokens.bg.surface,
            borderBottom: `1px solid ${tokens.border.default}`,
            fontSize: 11, fontWeight: 500, color: tokens.text.tertiary, letterSpacing: "0.04em", textTransform: "uppercase",
          }}>
            Directory Tree
          </div>

          {tree.map((item, i) => {
            const grant = getGrant(item.path);
            const isGranted = !!grant;

            return (
              <div key={item.path} style={{
                display: "flex", alignItems: "center", gap: 8,
                padding: "10px 16px", paddingLeft: 16 + item.depth * 24,
                borderBottom: i < tree.length - 1 ? `1px solid ${tokens.border.default}` : "none",
                background: isGranted ? tokens.accent.subtle : "transparent",
              }}>
                {isGranted ? <LockOpen size={15} style={{ color: tokens.accent.base }} />
                  : item.sensitive ? <Lock size={15} style={{ color: tokens.status.locked }} />
                  : <Folder size={15} style={{ color: tokens.text.tertiary }} />}

                <span style={{
                  flex: 1, fontFamily: "'Geist Mono', monospace", fontSize: 13,
                  color: isGranted ? tokens.text.primary : item.sensitive ? tokens.text.tertiary : tokens.text.secondary,
                }}>
                  {item.path}
                </span>

                {item.sensitive && !isGranted && <Badge color="red"><AlertTriangle size={10} /> blocked</Badge>}

                {isGranted && grant && (
                  <select value={grant.permission} onChange={e => updatePermission(item.path, e.target.value)} style={{
                    padding: "3px 8px", borderRadius: 4, fontSize: 11, fontWeight: 500,
                    background: tokens.bg.input, color: tokens.accent.base,
                    border: `1px solid ${tokens.accent.border}`, outline: "none", cursor: "pointer",
                    textTransform: "uppercase", letterSpacing: "0.04em",
                  }}>
                    <option value="read">Read</option>
                    <option value="write">Read + Write</option>
                    <option value="approval">Approval Req</option>
                  </select>
                )}

                {!item.sensitive && (
                  <button onClick={() => toggleGrant(item.path)} style={{
                    padding: "4px 10px", borderRadius: 4, fontSize: 11, fontWeight: 500,
                    background: isGranted ? tokens.status.lockedSubtle : "rgba(255,255,255,0.04)",
                    color: isGranted ? tokens.status.locked : tokens.text.tertiary,
                    border: `1px solid ${isGranted ? "rgba(239,68,68,0.2)" : tokens.border.default}`,
                    cursor: "pointer",
                  }}>
                    {isGranted ? "Revoke" : "Unlock"}
                  </button>
                )}
              </div>
            );
          })}
        </div>

        <div>
          <div style={{ border: `1px solid ${tokens.border.default}`, borderRadius: 8, overflow: "hidden" }}>
            <div style={{
              padding: "10px 16px", background: tokens.bg.surface,
              borderBottom: `1px solid ${tokens.border.default}`,
              fontSize: 11, fontWeight: 500, color: tokens.text.tertiary, letterSpacing: "0.04em", textTransform: "uppercase",
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
                <span style={{ flex: 1, fontFamily: "'Geist Mono', monospace", fontSize: 12, color: tokens.text.primary }}>
                  {g.path}
                </span>
                <Badge color={g.permission === "approval" ? "yellow" : g.permission === "write" ? "blue" : "accent"}>
                  {g.permission}
                </Badge>
              </div>
            ))}
          </div>

          <div style={{ border: `1px solid ${tokens.border.default}`, borderRadius: 8, overflow: "hidden", marginTop: 16 }}>
            <div style={{
              padding: "10px 16px", background: tokens.bg.surface,
              borderBottom: `1px solid ${tokens.border.default}`,
              fontSize: 11, fontWeight: 500, color: tokens.text.tertiary, letterSpacing: "0.04em", textTransform: "uppercase",
            }}>
              Always Blocked
            </div>
            {blocked.map((b, i) => (
              <div key={b.path} style={{
                padding: "8px 16px", display: "flex", alignItems: "center", gap: 8,
                borderBottom: i < blocked.length - 1 ? `1px solid ${tokens.border.default}` : "none",
              }}>
                <Lock size={14} style={{ color: tokens.status.locked }} />
                <span style={{ flex: 1, fontFamily: "'Geist Mono', monospace", fontSize: 12, color: tokens.text.tertiary }}>
                  {b.path}
                </span>
                <span style={{ fontSize: 11, color: tokens.text.tertiary }}>{b.reason}</span>
              </div>
            ))}
          </div>

          {/* Quick Unlock */}
          <div style={{ border: `1px solid ${tokens.border.default}`, borderRadius: 8, overflow: "hidden", marginTop: 16 }}>
            <div style={{
              padding: "10px 16px", background: tokens.bg.surface,
              borderBottom: `1px solid ${tokens.border.default}`,
              fontSize: 11, fontWeight: 500, color: tokens.text.tertiary, letterSpacing: "0.04em", textTransform: "uppercase",
            }}>
              Quick Unlock
            </div>
            {[
              { path: "~/Desktop", label: "Desktop" },
              { path: "~/Documents", label: "Documents" },
              { path: "~/Downloads", label: "Downloads" },
              { path: "~/Code", label: "Code / Projects" },
            ].map((item, i) => {
              const alreadyGranted = grants.some(g => g.path === item.path);
              return (
                <div key={item.path} style={{
                  padding: "8px 16px", display: "flex", alignItems: "center", gap: 8,
                  borderBottom: i < 3 ? `1px solid ${tokens.border.default}` : "none",
                }}>
                  {alreadyGranted
                    ? <LockOpen size={14} style={{ color: tokens.accent.base }} />
                    : <Folder size={14} style={{ color: tokens.text.tertiary }} />
                  }
                  <span style={{ flex: 1, fontSize: 13, color: alreadyGranted ? tokens.text.primary : tokens.text.secondary }}>
                    {item.label}
                  </span>
                  <span style={{ fontFamily: "'Geist Mono', monospace", fontSize: 11, color: tokens.text.tertiary, marginRight: 8 }}>
                    {item.path}
                  </span>
                  {!alreadyGranted && (
                    <button onClick={() => toggleGrant(item.path)} style={{
                      padding: "3px 10px", borderRadius: 4, fontSize: 11, fontWeight: 500,
                      background: "rgba(255,255,255,0.04)", color: tokens.accent.base,
                      border: `1px solid ${tokens.accent.border}`, cursor: "pointer",
                    }}>
                      Unlock
                    </button>
                  )}
                  {alreadyGranted && <Badge color="accent">granted</Badge>}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

const SessionsPage = () => {
  const sessions = [
    { id: "bk_7kx9m2", agent: "Claude via MCP", purpose: "Refund processing", secrets: 2, fs: 3, status: "active", expires: "48 min" },
    { id: "bk_p3n8w1", agent: "Custom GPT", purpose: "Code review", secrets: 1, fs: 2, status: "active", expires: "22 min" },
    { id: "bk_r5t2q8", agent: "OpenClaw Worker", purpose: "Deploy pipeline", secrets: 3, fs: 1, status: "expired", expires: "—" },
    { id: "bk_m1k4j6", agent: "Claude Code", purpose: "Feature development", secrets: 1, fs: 4, status: "revoked", expires: "—" },
  ];

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 32 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 600, color: tokens.text.primary, margin: 0 }}>Sessions</h1>
          <p style={{ fontSize: 14, color: tokens.text.secondary, margin: "6px 0 0" }}>
            Active and past agent sessions with scoped access.
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
          fontSize: 11, fontWeight: 500, color: tokens.text.tertiary, letterSpacing: "0.04em", textTransform: "uppercase",
        }}>
          <span>Session</span><span>Agent</span><span>Purpose</span>
          <span>Secrets</span><span>Folders</span><span>Status</span><span>TTL</span>
        </div>

        {sessions.map((s, i) => (
          <div key={s.id} style={{
            display: "grid", gridTemplateColumns: "120px 140px 1fr 80px 80px 80px 80px",
            padding: "12px 16px", alignItems: "center",
            borderBottom: i < sessions.length - 1 ? `1px solid ${tokens.border.default}` : "none",
          }}>
            <span style={{ fontFamily: "'Geist Mono', monospace", fontSize: 12, color: tokens.text.secondary }}>{s.id}</span>
            <span style={{ fontSize: 13, color: tokens.text.primary }}>{s.agent}</span>
            <span style={{ fontSize: 13, color: tokens.text.secondary }}>{s.purpose}</span>
            <span style={{ fontSize: 13, color: tokens.text.secondary }}>{s.secrets}</span>
            <span style={{ fontSize: 13, color: tokens.text.secondary }}>{s.fs}</span>
            <Badge color={s.status === "active" ? "accent" : s.status === "revoked" ? "red" : "gray"}>
              {s.status === "active" && "● "}{s.status}
            </Badge>
            <span style={{ fontSize: 12, color: tokens.text.secondary }}>{s.expires}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const AuditPage = () => {
  const entries = [
    { time: "14:32:05", session: "bk_7kx9m2", action: "API Request", target: "POST /v1/charges", secret: "STRIPE_PROD_KEY", status: "allowed", detail: "Charge $20.00" },
    { time: "14:31:58", session: "bk_7kx9m2", action: "File Read", target: "/project/src/handler.ts", secret: "—", status: "allowed", detail: "2.4 KB" },
    { time: "14:31:30", session: "bk_7kx9m2", action: "File Read", target: "/.ssh/id_rsa", secret: "—", status: "blocked", detail: "No grant" },
    { time: "14:30:15", session: "bk_7kx9m2", action: "API Request", target: "GET /v1/account", secret: "STRIPE_PROD_KEY", status: "blocked", detail: "Not in allowlist" },
  ];

  return (
    <div>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: tokens.text.primary, margin: 0 }}>Audit Log</h1>
        <p style={{ fontSize: 14, color: tokens.text.secondary, margin: "6px 0 0" }}>
          Immutable log of all agent actions.
        </p>
      </div>

      <div style={{ border: `1px solid ${tokens.border.default}`, borderRadius: 8, overflow: "hidden" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "80px 100px 100px 200px 140px 80px 1fr",
          padding: "10px 16px", background: tokens.bg.surface,
          borderBottom: `1px solid ${tokens.border.default}`,
          fontSize: 11, fontWeight: 500, color: tokens.text.tertiary, letterSpacing: "0.04em", textTransform: "uppercase",
        }}>
          <span>Time</span><span>Session</span><span>Action</span><span>Target</span>
          <span>Secret</span><span>Status</span><span>Detail</span>
        </div>

        {entries.map((e, i) => (
          <div key={i} style={{
            display: "grid", gridTemplateColumns: "80px 100px 100px 200px 140px 80px 1fr",
            padding: "10px 16px", alignItems: "center",
            borderBottom: i < entries.length - 1 ? `1px solid ${tokens.border.default}` : "none",
          }}>
            <span style={{ fontFamily: "'Geist Mono', monospace", fontSize: 12, color: tokens.text.tertiary }}>{e.time}</span>
            <span style={{ fontFamily: "'Geist Mono', monospace", fontSize: 12, color: tokens.text.secondary }}>{e.session}</span>
            <Badge color={e.action.includes("File") ? "blue" : "gray"}>{e.action}</Badge>
            <span style={{ fontFamily: "'Geist Mono', monospace", fontSize: 12, color: tokens.text.primary, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {e.target}
            </span>
            <span style={{ fontFamily: "'Geist Mono', monospace", fontSize: 12, color: tokens.text.secondary }}>{e.secret}</span>
            <Badge color={e.status === "allowed" ? "accent" : "red"}>{e.status}</Badge>
            <span style={{ fontSize: 12, color: tokens.text.secondary }}>{e.detail}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════
// SECURITY PAGE (2FA settings)
// ═══════════════════════════════════════════════════════════════════════════

const SecurityPage = () => {
  const [totpEnabled, setTotpEnabled] = useState<boolean | null>(null);
  const [setupData, setSetupData] = useState<{ otpauth_uri: string; secret: string } | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    getTotpStatus().then(s => setTotpEnabled(s.totp_enabled)).catch(() => {});
  }, []);

  const handleSetup = async () => {
    setError(null);
    try {
      const data = await setupTotp();
      setSetupData(data);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to start 2FA setup");
    }
  };

  const handleConfirm = async () => {
    if (!code) return;
    setSubmitting(true);
    setError(null);
    try {
      await confirmTotp(code);
      setTotpEnabled(true);
      setSetupData(null);
      setCode("");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Invalid code");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDisable = async () => {
    if (!code) return;
    setSubmitting(true);
    setError(null);
    try {
      await disableTotp(code);
      setTotpEnabled(false);
      setCode("");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Invalid code");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: tokens.text.primary, margin: 0 }}>Security</h1>
        <p style={{ fontSize: 14, color: tokens.text.secondary, margin: "6px 0 0" }}>
          Two-factor authentication and account security.
        </p>
      </div>

      {error && (
        <div style={{
          padding: "10px 14px", marginBottom: 16, borderRadius: 8,
          background: tokens.status.lockedSubtle, color: tokens.status.locked,
          border: `1px solid rgba(239,68,68,0.25)`, fontSize: 13,
          display: "flex", alignItems: "center", gap: 8,
        }}>
          <AlertTriangle size={14} /> {error}
          <button onClick={() => setError(null)} style={{
            marginLeft: "auto", background: "none", border: "none",
            color: tokens.status.locked, cursor: "pointer", padding: 2,
          }}><X size={14} /></button>
        </div>
      )}

      <div style={{ border: `1px solid ${tokens.border.default}`, borderRadius: 8, overflow: "hidden" }}>
        <div style={{
          padding: "16px", display: "flex", alignItems: "center", justifyContent: "space-between",
          borderBottom: setupData || totpEnabled ? `1px solid ${tokens.border.default}` : "none",
        }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 500, color: tokens.text.primary, marginBottom: 4 }}>
              Two-Factor Authentication (TOTP)
            </div>
            <div style={{ fontSize: 13, color: tokens.text.secondary }}>
              {totpEnabled === null ? "Loading..." : totpEnabled
                ? "Enabled — your account requires a code from your authenticator app on each login."
                : "Not enabled — add an extra layer of security to your account."}
            </div>
          </div>
          {totpEnabled === false && !setupData && (
            <button onClick={handleSetup} style={{
              display: "flex", alignItems: "center", gap: 6, padding: "8px 16px",
              background: tokens.accent.base, color: tokens.text.inverse,
              border: "none", borderRadius: 6, fontSize: 13, fontWeight: 500, cursor: "pointer",
              whiteSpace: "nowrap",
            }}>
              <Shield size={14} /> Enable 2FA
            </button>
          )}
          {totpEnabled === true && (
            <Badge color="accent">Enabled</Badge>
          )}
        </div>

        {/* Setup flow — show secret for authenticator app */}
        {setupData && !totpEnabled && (
          <div style={{ padding: "16px", borderBottom: `1px solid ${tokens.border.default}` }}>
            <div style={{ fontSize: 13, color: tokens.text.secondary, marginBottom: 12 }}>
              Add this account to your authenticator app (Google Authenticator, Authy, etc.):
            </div>
            <div style={{
              padding: "12px 16px", borderRadius: 8, background: tokens.bg.input,
              border: `1px solid ${tokens.border.default}`, marginBottom: 16,
            }}>
              <div style={{ fontSize: 11, color: tokens.text.tertiary, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 6 }}>
                Manual Entry Key
              </div>
              <div style={{
                fontFamily: "'Geist Mono', monospace", fontSize: 14, color: tokens.accent.base,
                wordBreak: "break-all", letterSpacing: "0.05em",
              }}>
                {setupData.secret}
              </div>
            </div>
            <div style={{ fontSize: 13, color: tokens.text.secondary, marginBottom: 12 }}>
              Then enter the 6-digit code to confirm setup:
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={code}
                onChange={e => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                placeholder="000000"
                style={{
                  width: 140, padding: "10px 14px", borderRadius: 8,
                  background: tokens.bg.input, border: `1px solid ${tokens.border.default}`,
                  color: tokens.text.primary, fontSize: 18, fontWeight: 600,
                  fontFamily: "'Geist Mono', monospace", textAlign: "center",
                  letterSpacing: "0.2em", outline: "none",
                }}
              />
              <button onClick={handleConfirm} disabled={code.length !== 6 || submitting} style={{
                display: "flex", alignItems: "center", gap: 6, padding: "10px 16px",
                background: code.length === 6 && !submitting ? tokens.accent.base : tokens.bg.elevated,
                color: code.length === 6 && !submitting ? tokens.text.inverse : tokens.text.tertiary,
                border: "none", borderRadius: 8, fontSize: 14, fontWeight: 500,
                cursor: code.length === 6 && !submitting ? "pointer" : "default",
              }}>
                {submitting ? <Loader size={14} style={{ animation: "spin 1s linear infinite" }} /> : <Check size={14} />} Confirm
              </button>
              <button onClick={() => { setSetupData(null); setCode(""); }} style={{
                padding: "10px 16px", background: "none",
                border: `1px solid ${tokens.border.default}`,
                borderRadius: 8, fontSize: 14, color: tokens.text.secondary, cursor: "pointer",
              }}>
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Disable flow */}
        {totpEnabled === true && (
          <div style={{ padding: "16px" }}>
            <div style={{ fontSize: 13, color: tokens.text.secondary, marginBottom: 12 }}>
              To disable 2FA, enter a code from your authenticator app:
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={code}
                onChange={e => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                placeholder="000000"
                style={{
                  width: 140, padding: "10px 14px", borderRadius: 8,
                  background: tokens.bg.input, border: `1px solid ${tokens.border.default}`,
                  color: tokens.text.primary, fontSize: 18, fontWeight: 600,
                  fontFamily: "'Geist Mono', monospace", textAlign: "center",
                  letterSpacing: "0.2em", outline: "none",
                }}
              />
              <button onClick={handleDisable} disabled={code.length !== 6 || submitting} style={{
                display: "flex", alignItems: "center", gap: 6, padding: "10px 16px",
                background: code.length === 6 && !submitting ? tokens.status.locked : tokens.bg.elevated,
                color: code.length === 6 && !submitting ? "#fff" : tokens.text.tertiary,
                border: "none", borderRadius: 8, fontSize: 14, fontWeight: 500,
                cursor: code.length === 6 && !submitting ? "pointer" : "default",
              }}>
                {submitting ? <Loader size={14} style={{ animation: "spin 1s linear infinite" }} /> : <X size={14} />} Disable 2FA
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════
// LOGIN / REGISTER SCREEN
// ═══════════════════════════════════════════════════════════════════════════

const LoginScreen = ({ onSuccess }: { onSuccess: () => void }) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isRegister, setIsRegister] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // TOTP verification state
  const [totpToken, setTotpToken] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;
    setSubmitting(true);
    setError(null);
    try {
      if (isRegister) {
        await register(email, password);
        onSuccess();
      } else {
        const result = await login(email, password);
        if (result.requires_totp && result.totp_token) {
          setTotpToken(result.totp_token);
        } else {
          onSuccess();
        }
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Authentication failed");
    } finally {
      setSubmitting(false);
    }
  };

  const handleTotpVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpToken || !totpCode) return;
    setSubmitting(true);
    setError(null);
    try {
      await verifyTotp(totpToken, totpCode);
      onSuccess();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Invalid code");
    } finally {
      setSubmitting(false);
    }
  };

  const wrapper = (children: React.ReactNode) => (
    <div style={{
      minHeight: "100vh", background: tokens.bg.root,
      fontFamily: "'Geist', -apple-system, BlinkMacSystemFont, sans-serif",
      display: "flex", alignItems: "center", justifyContent: "center",
    }}>
      <div style={{ width: 380, padding: 24 }}>
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <div style={{
            width: 56, height: 56, borderRadius: 16, margin: "0 auto 16px",
            background: `linear-gradient(135deg, ${tokens.accent.base}, #00a85a)`,
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <Shield size={28} style={{ color: tokens.text.inverse }} />
          </div>
          <h1 style={{ fontSize: 28, fontWeight: 600, color: tokens.text.primary, margin: "0 0 8px" }}>
            BlindKey
          </h1>
        </div>

        {error && (
          <div style={{
            padding: "10px 14px", marginBottom: 16, borderRadius: 8,
            background: tokens.status.lockedSubtle, color: tokens.status.locked,
            border: `1px solid rgba(239,68,68,0.25)`, fontSize: 13,
            display: "flex", alignItems: "center", gap: 8,
          }}>
            <AlertTriangle size={14} /> {error}
          </div>
        )}

        {children}
      </div>
    </div>
  );

  // TOTP verification step
  if (totpToken) {
    return wrapper(
      <>
        <p style={{ fontSize: 15, color: tokens.text.secondary, margin: "0 0 24px", textAlign: "center" }}>
          Enter the 6-digit code from your authenticator app
        </p>
        <form onSubmit={handleTotpVerify}>
          <div style={{ marginBottom: 24 }}>
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              value={totpCode}
              onChange={e => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="000000"
              autoFocus
              style={{
                width: "100%", padding: "16px 14px", borderRadius: 8,
                background: tokens.bg.input, border: `1px solid ${tokens.border.default}`,
                color: tokens.text.primary, fontSize: 24, fontWeight: 600,
                fontFamily: "'Geist Mono', monospace", textAlign: "center",
                letterSpacing: "0.3em", outline: "none", boxSizing: "border-box",
              }}
            />
          </div>
          <button type="submit" disabled={totpCode.length !== 6 || submitting} style={{
            width: "100%", padding: "12px", borderRadius: 8,
            background: totpCode.length === 6 && !submitting ? tokens.accent.base : tokens.bg.elevated,
            color: totpCode.length === 6 && !submitting ? tokens.text.inverse : tokens.text.tertiary,
            border: "none", fontSize: 15, fontWeight: 600,
            cursor: totpCode.length === 6 && !submitting ? "pointer" : "default",
            display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
          }}>
            {submitting ? <><Loader size={16} style={{ animation: "spin 1s linear infinite" }} /> Verifying...</> : "Verify"}
          </button>
        </form>
        <div style={{ textAlign: "center", marginTop: 20 }}>
          <button onClick={() => { setTotpToken(null); setTotpCode(""); setError(null); }} style={{
            background: "none", border: "none", color: tokens.text.secondary,
            fontSize: 13, cursor: "pointer", textDecoration: "underline",
            textDecorationColor: tokens.border.hover,
          }}>
            Back to login
          </button>
        </div>
      </>
    );
  }

  // Email/password login
  return wrapper(
    <>
      <p style={{ fontSize: 15, color: tokens.text.secondary, margin: "-24px 0 24px", textAlign: "center" }}>
        {isRegister ? "Create your account" : "Sign in to your vault"}
      </p>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: 12 }}>
          <label style={{ display: "block", fontSize: 12, color: tokens.text.secondary, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.04em" }}>
            Email
          </label>
          <input
            type="email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            placeholder="you@example.com"
            autoComplete="email"
            style={{
              width: "100%", padding: "12px 14px", borderRadius: 8,
              background: tokens.bg.input, border: `1px solid ${tokens.border.default}`,
              color: tokens.text.primary, fontSize: 14, outline: "none",
              boxSizing: "border-box",
            }}
          />
        </div>
        <div style={{ marginBottom: 24 }}>
          <label style={{ display: "block", fontSize: 12, color: tokens.text.secondary, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.04em" }}>
            Password
          </label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder={isRegister ? "Min 8 characters" : "Your password"}
            autoComplete={isRegister ? "new-password" : "current-password"}
            style={{
              width: "100%", padding: "12px 14px", borderRadius: 8,
              background: tokens.bg.input, border: `1px solid ${tokens.border.default}`,
              color: tokens.text.primary, fontSize: 14, outline: "none",
              boxSizing: "border-box",
            }}
          />
        </div>
        <button type="submit" disabled={!email || !password || submitting} style={{
          width: "100%", padding: "12px", borderRadius: 8,
          background: email && password && !submitting ? tokens.accent.base : tokens.bg.elevated,
          color: email && password && !submitting ? tokens.text.inverse : tokens.text.tertiary,
          border: "none", fontSize: 15, fontWeight: 600, cursor: email && password && !submitting ? "pointer" : "default",
          display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
        }}>
          {submitting ? <><Loader size={16} style={{ animation: "spin 1s linear infinite" }} /> {isRegister ? "Creating..." : "Signing in..."}</> : isRegister ? "Create Account" : "Sign In"}
        </button>
      </form>

      <div style={{ textAlign: "center", marginTop: 20 }}>
        <button onClick={() => { setIsRegister(!isRegister); setError(null); }} style={{
          background: "none", border: "none", color: tokens.text.secondary,
          fontSize: 13, cursor: "pointer", textDecoration: "underline",
          textDecorationColor: tokens.border.hover,
        }}>
          {isRegister ? "Already have an account? Sign in" : "Need an account? Register"}
        </button>
      </div>
    </>
  );
};

// ═══════════════════════════════════════════════════════════════════════════
// MAIN DASHBOARD - Mode Toggle
// ═══════════════════════════════════════════════════════════════════════════

type PageId = "secrets" | "filesystem" | "sessions" | "audit" | "security";

export default function BlindKeyDashboard() {
  const [authed, setAuthed] = useState(isLoggedIn());
  const [expertMode, setExpertMode] = useState(false);
  const [activePage, setActivePage] = useState<PageId>("secrets");
  const [sidebarHover, setSidebarHover] = useState<string | null>(null);

  // Secrets state — fetched from API
  const [secrets, setSecrets] = useState<SecretMetadata[]>([]);
  const [secretsLoading, setSecretsLoading] = useState(true);

  // Filesystem grants (persisted via API)
  const [grants, setGrants] = useState<FsGrant[]>([]);

  const refreshSecrets = useCallback(async () => {
    try {
      const data = await fetchSecrets();
      setSecrets(data);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setAuthed(false);
      }
    } finally {
      setSecretsLoading(false);
    }
  }, []);

  const refreshGrants = useCallback(async () => {
    try {
      const data = await fetchGrants();
      setGrants(data.map(g => ({
        id: g.id,
        path: g.path,
        permission: g.requires_approval ? "approval" : g.permissions.includes("write") ? "write" : "read",
        recursive: g.recursive,
        approval: g.requires_approval,
      })));
    } catch {
      // Grants endpoint may not exist on older API servers — degrade gracefully
    }
  }, []);

  // Fetch secrets and grants on mount
  useEffect(() => {
    if (authed) {
      refreshSecrets();
      refreshGrants();
    }
  }, [authed, refreshSecrets, refreshGrants]);

  const handleLogout = () => {
    clearToken();
    setAuthed(false);
    setSecrets([]);
  };

  // Not logged in — show login screen
  if (!authed) {
    return <LoginScreen onSuccess={() => setAuthed(true)} />;
  }

  // Simple mode
  if (!expertMode) {
    return (
      <div style={{
        minHeight: "100vh", background: tokens.bg.root,
        fontFamily: "'Geist', -apple-system, BlinkMacSystemFont, sans-serif",
        color: tokens.text.primary,
      }}>
        <SimpleDashboard
          secrets={secrets}
          refreshSecrets={refreshSecrets}
          loading={secretsLoading}
          grants={grants}
          setGrants={setGrants}
          onSwitchToExpert={() => setExpertMode(true)}
          onLogout={handleLogout}
        />
      </div>
    );
  }

  // Expert mode
  const nav: { id: PageId; label: string; icon: typeof Key }[] = [
    { id: "secrets", label: "Secrets", icon: Key },
    { id: "filesystem", label: "Filesystem", icon: FolderOpen },
    { id: "sessions", label: "Sessions", icon: Shield },
    { id: "audit", label: "Audit Log", icon: Activity },
    { id: "security", label: "Security", icon: Lock },
  ];

  const pages: Record<PageId, React.ReactNode> = {
    secrets: <SecretsPage secrets={secrets} refreshSecrets={refreshSecrets} loading={secretsLoading} />,
    filesystem: <FilesystemPage grants={grants} setGrants={setGrants} />,
    sessions: <SessionsPage />,
    audit: <AuditPage />,
    security: <SecurityPage />,
  };

  return (
    <div style={{
      display: "flex", minHeight: "100vh", background: tokens.bg.root,
      fontFamily: "'Geist', -apple-system, BlinkMacSystemFont, sans-serif",
      color: tokens.text.primary,
    }}>
      {/* Sidebar */}
      <div style={{
        width: 240, borderRight: `1px solid ${tokens.border.default}`,
        display: "flex", flexDirection: "column",
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
          <Badge color="yellow">Expert</Badge>
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
                  fontSize: 13, fontWeight: active ? 500 : 400, textAlign: "left",
                  position: "relative",
                }}
              >
                {active && <div style={{
                  position: "absolute", left: -8, top: "50%", transform: "translateY(-50%)",
                  width: 3, height: 16, borderRadius: 2, background: tokens.accent.base,
                }} />}
                <Icon size={17} style={{ opacity: active ? 1 : 0.5 }} />
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Bottom sidebar actions */}
        <div style={{ padding: "12px 16px", borderTop: `1px solid ${tokens.border.default}`, display: "flex", flexDirection: "column", gap: 8 }}>
          <button onClick={() => setExpertMode(false)} style={{
            width: "100%", display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
            padding: "8px", background: "none", border: `1px solid ${tokens.border.default}`,
            borderRadius: 6, color: tokens.text.secondary, fontSize: 12, cursor: "pointer",
          }}>
            Switch to Simple Mode
          </button>
          <button onClick={handleLogout} style={{
            width: "100%", display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
            padding: "8px", background: "none", border: "none",
            color: tokens.text.tertiary, fontSize: 12, cursor: "pointer",
          }}>
            <LogOut size={14} /> Log out
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div style={{ marginLeft: 240, flex: 1, padding: "32px 40px", maxWidth: 1200 }}>
        {pages[activePage]}
      </div>
    </div>
  );
}
