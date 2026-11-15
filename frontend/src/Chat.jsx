// NetCollab - real-time secure chat page (Member 2).
// Live messages travel over the RSA/AES-GCM channel in ./comm/secureSocket.js;
// history, unread counters and contacts come from the Django REST API (/api/comm/...).

import React, { useCallback, useEffect, useRef, useState } from "react";
import { Hash, Send, Lock, MessageSquare } from "lucide-react";
import api from "./api";
import { SecureSocket } from "./comm/secureSocket";

const WS_URL = import.meta.env.VITE_WS_URL || "ws://127.0.0.1:9001";

const keyOf = (c) => `${c.type === "channel" ? "c" : "d"}:${c.id}`;
const readBody = (c) => (c.type === "channel" ? { channel_id: c.id } : { dm_user_id: c.id });
const timeOf = (iso) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

function mergeById(a, b) {
  const map = new Map();
  [...a, ...b].forEach((m) => map.set(m.id, m));
  return [...map.values()].sort((x, y) => x.id - y.id);
}

function bump(u, m) {
  const group = m.kind === "channel" ? "channels" : "dms";
  const id = String(m.kind === "channel" ? m.channel_id : m.sender_id);
  return { ...u, [group]: { ...u[group], [id]: (u[group][id] || 0) + 1 }, total: u.total + 1 };
}

function clearUnread(u, conv) {
  const group = conv.type === "channel" ? "channels" : "dms";
  const n = u[group][String(conv.id)] || 0;
  if (!n) return u;
  const next = { ...u[group] };
  delete next[String(conv.id)];
  return { ...u, [group]: next, total: Math.max(0, u.total - n) };
}

function Badge({ n }) {
  return n ? (
    <span className="ml-auto bg-indigo-600 text-white text-xs rounded-full px-2 py-0.5">{n}</span>
  ) : null;
}

export default function Chat({ Shell }) {
  const [teams, setTeams] = useState([]);
  const [contacts, setContacts] = useState([]);
  const [unread, setUnread] = useState({ channels: {}, dms: {}, total: 0 });
  const [online, setOnline] = useState(new Set());
  const [active, setActive] = useState(null);
  const [messages, setMessages] = useState({});
  const [status, setStatus] = useState("connecting");
  const [me, setMe] = useState(null);
  const [text, setText] = useState("");
  const [error, setError] = useState("");

  const socketRef = useRef(null);
  const activeRef = useRef(null);
  const meRef = useRef(null);
  const endRef = useRef(null);

  const flash = (msg) => {
    setError(msg);
    setTimeout(() => setError(""), 5000);
  };

  // ---------------------------------------------------------------- REST data
  useEffect(() => {
    (async () => {
      try {
        const [t, c, u] = await Promise.all([
          api.get("/teams/"),
          api.get("/comm/contacts/"),
          api.get("/comm/unread/"),
        ]);
        const list = Array.isArray(t.data) ? t.data : t.data.results || [];
        const withChannels = await Promise.all(
          list.map(async (team) => ({
            id: team.id,
            name: team.name,
            channels: (await api.get(`/teams/${team.id}/channels/`)).data,
          }))
        );
        setTeams(withChannels);
        setContacts(c.data);
        setUnread(u.data);
      } catch (e) {
        flash("Could not load chat data: " + (e.response?.status || e.message));
      }
    })();
  }, []);

  // ---------------------------------------------------------- live events
  const handleEvent = useCallback((ev) => {
    if (ev.type === "MESSAGE") {
      const m = ev.message;
      const mine = m.sender_id === meRef.current?.id;
      const key = m.kind === "channel" ? `c:${m.channel_id}` : `d:${mine ? m.recipient_id : m.sender_id}`;
      setMessages((prev) =>
        prev[key] && !prev[key].some((x) => x.id === m.id) ? { ...prev, [key]: [...prev[key], m] } : prev
      );
      const a = activeRef.current;
      if (a && keyOf(a) === key) {
        if (!mine) api.post("/comm/notifications/read/", readBody(a)).catch(() => {});
      } else if (!mine) {
        setUnread((u) => bump(u, m));
      }
    } else if (ev.type === "PRESENCE_LIST") {
      setOnline(new Set(ev.online));
    } else if (ev.type === "PRESENCE") {
      setOnline((prev) => {
        const next = new Set(prev);
        ev.online ? next.add(ev.user_id) : next.delete(ev.user_id);
        return next;
      });
    } else if (ev.type === "ERROR") {
      flash(ev.message || "Server error");
    }
  }, []);

  // ------------------------------------------------- secure socket + reconnect
  useEffect(() => {
    let closed = false;
    let retry = 0;
    let retryTimer;
    let pingTimer;

    const schedule = () => {
      clearInterval(pingTimer);
      retry += 1;
      retryTimer = setTimeout(connect, Math.min(1000 * 2 ** retry, 15000));
    };

    async function connect() {
      setStatus("connecting");
      try {
        await api.get("/accounts/profile/"); // refreshes the JWT if it has expired
        let fingerprint = null;
        try {
          fingerprint = (await api.get("/comm/server-info/")).data.fingerprint;
        } catch { /* pinning is optional */ }

        const sock = new SecureSocket(WS_URL, {
          onMessage: handleEvent,
          onClose: () => {
            if (!closed) {
              setStatus("offline");
              schedule();
            }
          },
        });
        const user = await sock.connect(localStorage.getItem("access"), fingerprint);
        if (closed) {
          sock.close();
          return;
        }
        socketRef.current = sock;
        meRef.current = user;
        setMe(user);
        setStatus("online");
        retry = 0;
        pingTimer = setInterval(() => sock.send({ type: "PING" }).catch(() => {}), 30000);
      } catch (e) {
        if (!closed) {
          setStatus("offline");
          flash(e.message);
          schedule();
        }
      }
    }

    connect();
    return () => {
      closed = true;
      clearTimeout(retryTimer);
      clearInterval(pingTimer);
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [handleEvent]);

  // --------------------------------------------------------------- actions
  const open = async (conv) => {
    setActive(conv);
    activeRef.current = conv;
    const key = keyOf(conv);
    setMessages((p) => ({ ...p, [key]: p[key] || [] })); // live messages may now append
    const url = conv.type === "channel" ? `/comm/channels/${conv.id}/messages/` : `/comm/dm/${conv.id}/messages/`;
    try {
      const { data } = await api.get(url);
      setMessages((p) => ({ ...p, [key]: mergeById(p[key] || [], data.results) }));
    } catch (e) {
      flash(e.response?.data?.error || "Could not load history");
    }
    api.post("/comm/notifications/read/", readBody(conv)).catch(() => {});
    setUnread((u) => clearUnread(u, conv));
  };

  const send = async (e) => {
    e.preventDefault();
    const body = text.trim();
    if (!body || !active || status !== "online") return;
    const payload =
      active.type === "channel"
        ? { type: "SEND_CHANNEL", channel_id: active.id, content: body, client_id: String(Date.now()) }
        : { type: "SEND_DM", to_user_id: active.id, content: body, client_id: String(Date.now()) };
    try {
      await socketRef.current.send(payload);
      setText("");
    } catch {
      flash("Message could not be sent.");
    }
  };

  const list = active ? messages[keyOf(active)] || [] : [];
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [list.length, active]);

  const statusStyle = {
    online: "bg-emerald-100 text-emerald-700",
    connecting: "bg-amber-100 text-amber-700",
    offline: "bg-red-100 text-red-700",
  }[status];

  const Conv = ({ conv, icon, label, count, dot }) => (
    <button
      onClick={() => open(conv)}
      className={`w-full flex items-center gap-2 px-3 py-2 rounded-xl text-left text-sm ${
        active && keyOf(active) === keyOf(conv) ? "bg-indigo-50 text-indigo-700 font-semibold" : "hover:bg-slate-100"
      }`}
    >
      {icon}
      <span className="truncate">{label}</span>
      {dot !== undefined && (
        <span className={`w-2 h-2 rounded-full ${dot ? "bg-emerald-500" : "bg-slate-300"}`} title={dot ? "online" : "offline"} />
      )}
      <Badge n={count} />
    </button>
  );

  return (
    <Shell active="/chat">
      <div className="flex flex-col md:flex-row gap-4 md:h-[calc(100vh-4.5rem)]">
        <aside className="md:w-72 shrink-0 bg-white border rounded-2xl p-3 overflow-y-auto max-h-80 md:max-h-none">
          <div className="flex items-center justify-between px-2 pb-1">
            <h1 className="font-bold text-lg flex items-center gap-2">
              <MessageSquare size={18} /> Chat
              {unread.total > 0 && <span className="text-xs bg-indigo-600 text-white rounded-full px-2">{unread.total}</span>}
            </h1>
            <span className={`text-xs px-2 py-1 rounded-full ${statusStyle}`}>{status}</span>
          </div>

          {teams.map((team) => (
            <div key={team.id}>
              <p className="text-xs uppercase tracking-wide text-slate-400 px-3 mt-4 mb-1">{team.name}</p>
              {team.channels.length === 0 && <p className="text-xs text-slate-400 px-3">No channels yet</p>}
              {team.channels.map((ch) => (
                <Conv
                  key={ch.id}
                  conv={{ type: "channel", id: ch.id, title: `# ${ch.name}`, sub: team.name }}
                  icon={<Hash size={15} className="text-slate-400" />}
                  label={ch.name}
                  count={unread.channels[String(ch.id)]}
                />
              ))}
            </div>
          ))}

          <p className="text-xs uppercase tracking-wide text-slate-400 px-3 mt-5 mb-1">Direct messages</p>
          {contacts.length === 0 && <p className="text-xs text-slate-400 px-3">Add teammates to start chatting</p>}
          {contacts.map((u) => (
            <Conv
              key={u.id}
              conv={{ type: "dm", id: u.id, title: u.full_name || u.username, sub: `@${u.username}` }}
              label={u.full_name || u.username}
              count={unread.dms[String(u.id)]}
              dot={online.has(u.id)}
            />
          ))}
        </aside>

        <section className="flex-1 min-h-[24rem] bg-white border rounded-2xl flex flex-col min-w-0">
          {!active ? (
            <div className="m-auto text-center text-slate-400 p-8">
              <MessageSquare className="mx-auto mb-3" size={36} />
              Pick a channel or a teammate to start chatting.
            </div>
          ) : (
            <>
              <header className="px-5 py-3 border-b flex items-center justify-between">
                <div>
                  <h2 className="font-bold">{active.title}</h2>
                  <p className="text-xs text-slate-400">{active.sub}</p>
                </div>
                <span className="hidden sm:flex items-center gap-1 text-xs text-slate-400" title="RSA-2048 key exchange, AES-256-GCM encrypted">
                  <Lock size={13} /> Encrypted
                </span>
              </header>

              <div className="flex-1 overflow-y-auto p-5 space-y-3">
                {list.length === 0 && <p className="text-center text-sm text-slate-400">No messages yet - say hello!</p>}
                {list.map((m) => {
                  const mine = m.sender_id === me?.id;
                  return (
                    <div key={m.id} className={`flex ${mine ? "justify-end" : "justify-start"}`}>
                      <div className={`max-w-[75%] rounded-2xl px-4 py-2 ${mine ? "bg-indigo-600 text-white" : "bg-slate-100"}`}>
                        {!mine && active.type === "channel" && (
                          <p className="text-xs font-semibold text-indigo-600">{m.sender_username}</p>
                        )}
                        <p className="whitespace-pre-wrap break-words">{m.content}</p>
                        <p className={`text-[10px] mt-1 ${mine ? "text-indigo-200" : "text-slate-400"}`}>{timeOf(m.created_at)}</p>
                      </div>
                    </div>
                  );
                })}
                <div ref={endRef} />
              </div>

              {error && <p className="px-5 text-sm text-red-600">{error}</p>}
              <form onSubmit={send} className="p-4 border-t flex gap-3">
                <input
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  maxLength={4000}
                  placeholder={status === "online" ? "Type a message..." : "Reconnecting..."}
                  disabled={status !== "online"}
                  className="flex-1 border rounded-xl px-4 py-3 outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-slate-50"
                />
                <button
                  disabled={status !== "online" || !text.trim()}
                  className="bg-indigo-600 hover:bg-indigo-700 disabled:opacity-40 text-white rounded-xl px-5 flex items-center gap-2"
                >
                  <Send size={16} /> Send
                </button>
              </form>
            </>
          )}
          {!active && error && <p className="px-5 pb-4 text-sm text-red-600">{error}</p>}
        </section>
      </div>
    </Shell>
  );
}
