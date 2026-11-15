
import React, { useEffect, useState } from "react";
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  Link,
  useNavigate
} from "react-router-dom";

import {
  LayoutDashboard,
  Users,
  FolderKanban,
  Folder,
  LogOut,
  Plus,
  Wallet,
  CheckCircle2,
  MessageSquare
} from "lucide-react";

import { BrowserProvider } from "ethers";
import api from "./api";
import Chat from "./Chat";
import Artifacts from "./artifacts/Artifacts";
// ==========================================
// AUTHENTICATION: LOGIN AND REGISTRATION
// ==========================================

function Auth({ mode }) {
  const nav = useNavigate();

  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
    full_name: ""
  });

  const [error, setError] = useState("");

  const change = (e) => {
    setForm({
      ...form,
      [e.target.name]: e.target.value
    });
  };

  const submit = async (e) => {
    e.preventDefault();
    setError("");

    try {
      if (mode === "register") {
        await api.post("/accounts/register/", form);
        nav("/login");
      } else {
        const response = await api.post(
          "/accounts/login/",
          {
            username: form.username,
            password: form.password
          }
        );

        if (!response.data.access) {
          throw new Error("Access token was not returned by the server.");
        }

        localStorage.setItem("access", response.data.access);

        if (response.data.refresh) {
          localStorage.setItem("refresh", response.data.refresh);
        }

        nav("/");
      }
    } catch (err) {
      setError(
        JSON.stringify(
          err.response?.data || err.message || "Request failed"
        )
      );
    }
  };

  return (
    <div className="min-h-screen grid md:grid-cols-2 bg-slate-950">

      <div className="hidden md:flex flex-col justify-between p-12 text-white bg-gradient-to-br from-indigo-700 to-slate-950">
        <div className="text-2xl font-bold">NetCollab.</div>

        <div>
          <p className="text-indigo-200 uppercase tracking-widest text-sm">
            Collaborate. Build. Verify.
          </p>

          <h1 className="text-5xl font-bold mt-4 leading-tight">
            One workspace
            <br />
            for every team.
          </h1>

          <p className="text-slate-300 mt-5 max-w-md">
            Manage projects, coordinate tasks and keep your team connected.
          </p>
        </div>

        <p className="text-slate-400 text-sm">
          NetCollab · Team collaboration platform
        </p>
      </div>

      <div className="flex items-center justify-center p-6">
        <form
          onSubmit={submit}
          className="bg-white rounded-2xl p-8 w-full max-w-md shadow-2xl space-y-4"
        >
          <div className="text-indigo-600 font-bold text-xl">
            NetCollab
          </div>

          <h2 className="text-3xl font-bold">
            {mode === "register" ? "Create account" : "Welcome back"}
          </h2>

          <p className="text-slate-500">
            {mode === "register"
              ? "Start collaborating with your team."
              : "Sign in to continue to your workspace."}
          </p>

          {(mode === "register"
            ? ["full_name", "username", "email", "password"]
            : ["username", "password"]
          ).map((key) => (
            <input
              key={key}
              name={key}
              type={
                key === "password"
                  ? "password"
                  : key === "email"
                  ? "email"
                  : "text"
              }
              placeholder={key.replace("_", " ").replace(/^\w/, c => c.toUpperCase())}
              required
              minLength={key === "password" ? 8 : undefined}
              value={form[key]}
              onChange={change}
              className="w-full border border-slate-200 rounded-xl px-4 py-3 outline-none focus:ring-2 focus:ring-indigo-500"
            />
          ))}

          {error && (
            <p className="text-sm text-red-600 break-words">
              {error}
            </p>
          )}

          <button
            type="submit"
            className="w-full bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl py-3 font-semibold"
          >
            {mode === "register" ? "Create account" : "Sign in"}
          </button>

          <p className="text-sm text-center text-slate-500">
            {mode === "register"
              ? "Already have an account?"
              : "New to NetCollab?"}

            {" "}

            <Link
              className="text-indigo-600 font-semibold"
              to={mode === "register" ? "/login" : "/register"}
            >
              {mode === "register" ? "Sign in" : "Create account"}
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}

// ==========================================
// COMMON DASHBOARD LAYOUT
// ==========================================

function Shell({ children, active }) {
  const nav = useNavigate();

  const logout = () => {
    localStorage.removeItem("access");
    localStorage.removeItem("refresh");
    nav("/login");
  };

  const items = [
    ["Overview", "/", LayoutDashboard],
    ["Teams", "/teams", Users],
    ["Projects", "/projects", FolderKanban],
    ["Artifacts", "/artifacts", Folder],
    ["Chat", "/chat", MessageSquare]
  ];

  return (
    <div className="min-h-screen bg-slate-50 md:flex">

      <aside className="md:w-64 bg-slate-950 text-white p-5 flex md:flex-col justify-between">

        <div>
          <div className="text-2xl font-bold mb-10">
            NetCollab<span className="text-indigo-400">.</span>
          </div>

          <nav className="flex md:flex-col gap-2">
            {items.map(([name, path, Icon]) => (
              <Link
                key={path}
                to={path}
                className={`flex items-center gap-3 px-4 py-3 rounded-xl ${
                  active === path
                    ? "bg-indigo-600"
                    : "text-slate-300 hover:bg-slate-800"
                }`}
              >
                <Icon size={18} />
                {name}
              </Link>
            ))}
          </nav>
        </div>

        <button
          onClick={logout}
          className="flex items-center gap-2 text-slate-300 p-3"
        >
          <LogOut size={18} />
          Sign out
        </button>

      </aside>

      <main className="flex-1 p-5 md:p-9 max-w-7xl">
        {children}
      </main>

    </div>
  );
}

// ==========================================
// DASHBOARD
// ==========================================

function Dashboard() {
  const [profile, setProfile] = useState(null);
  const [teams, setTeams] = useState([]);
  const [projects, setProjects] = useState([]);
  const [dashboardError, setDashboardError] = useState("");
  const [editingProfile, setEditingProfile] = useState(false);
  const [profileForm, setProfileForm] = useState({
    full_name: "",
    email: ""
  });

  const load = async () => {
    setDashboardError("");

    const requests = [
      {
        name: "Profile",
        request: api.get("/accounts/profile/")
      },
      {
        name: "Teams",
        request: api.get("/teams/")
      },
      {
        name: "Projects",
        request: api.get("/projects/")
      }
    ];

    const results = await Promise.allSettled(
      requests.map(item => item.request)
    );

    const errors = [];

    results.forEach((result, index) => {
      const name = requests[index].name;

      if (result.status === "fulfilled") {
        const data = result.value.data;

        if (name === "Profile") {
          setProfile(data);
        }

        if (name === "Teams") {
          setTeams(Array.isArray(data) ? data : data.results || []);
        }

        if (name === "Projects") {
          setProjects(Array.isArray(data) ? data : data.results || []);
        }
      } else {
        const error = result.reason;

        console.error(`${name} API failed:`, {
          url: error.config?.url,
          status: error.response?.status,
          response: error.response?.data,
          message: error.message
        });

        errors.push(
          `${name}: ${error.response?.status || error.message}`
        );
      }
    });

    if (errors.length > 0) {
      setDashboardError(
        "Some dashboard information could not load: " +
        errors.join(" | ")
      );
    }
  };

  useEffect(() => {
    load();
  }, []);

  const wallet = async () => {
    try {
      if (!window.ethereum) {
        throw new Error("Please install MetaMask first.");
      }

      const provider = new BrowserProvider(window.ethereum);

      const accounts = await provider.send(
        "eth_requestAccounts",
        []
      );

      await api.post("/accounts/wallet/", {
        wallet_address: accounts[0]
      });

      await load();

      alert("Wallet connected successfully!");
    } catch (error) {
      alert(error.response?.data
        ? JSON.stringify(error.response.data)
        : error.message
      );
    }
  };

  const startEditProfile = () => {
    setProfileForm({
      full_name: profile?.full_name || "",
      email: profile?.email || ""
    });
    setEditingProfile(true);
  };

  const saveProfile = async (e) => {
    e.preventDefault();

    try {
      await api.patch("/accounts/profile/", profileForm);
      await load();
      setEditingProfile(false);
      alert("Profile updated successfully!");
    } catch (error) {
      alert(JSON.stringify(error.response?.data || error.message));
    }
  };

  const taskCount = projects.reduce(
    (total, project) => total + (project.tasks?.length || 0),
    0
  );

  return (
    <Shell active="/">

      <header className="mb-8">
        <p className="text-slate-500">Workspace</p>

        <h1 className="text-3xl font-bold mt-1">
          Good to see you, {profile?.full_name || "there"}.
        </h1>
      </header>

      {dashboardError && (
        <div className="bg-amber-50 border border-amber-300 text-amber-800 rounded-xl p-4 mb-6 break-words">
          <p className="font-semibold">Dashboard loading warning</p>
          <p className="text-sm mt-1">{dashboardError}</p>
          <button
            onClick={load}
            className="underline text-sm mt-2"
          >
            Retry
          </button>
        </div>
      )}

      <div className="grid sm:grid-cols-3 gap-4 mb-7">

        {[
          ["Teams", teams.length, Users],
          ["Projects", projects.length, FolderKanban],
          ["Tasks", taskCount, CheckCircle2]
        ].map(([name, value, Icon]) => (
          <div
            key={name}
            className="bg-white border border-slate-200 rounded-2xl p-5"
          >
            <Icon className="text-indigo-600" />

            <p className="text-slate-500 mt-4">{name}</p>

            <p className="text-3xl font-bold">{value}</p>
          </div>
        ))}

      </div>

      <div className="bg-white border rounded-2xl p-6 mb-6">
        <div className="flex justify-between items-center gap-3 flex-wrap">
          <div>
            <h2 className="font-bold text-lg">Your profile</h2>
            <p className="text-slate-700">{profile?.full_name || ""}</p>
            <p className="text-slate-500 text-sm">{profile?.email || ""}</p>
          </div>

          <div className="flex gap-2 flex-wrap">
            <button
              type="button"
              onClick={startEditProfile}
              className="border rounded-xl px-4 py-2"
            >
              Edit Profile
            </button>

            <button
              type="button"
              onClick={wallet}
              className="bg-slate-900 text-white px-4 py-2 rounded-xl flex gap-2 items-center"
            >
              <Wallet size={17} />
              {profile?.wallet_address
                ? "Reconnect wallet"
                : "Connect MetaMask"}
            </button>
          </div>
        </div>

        {profile?.wallet_address && (
          <p className="text-xs text-slate-500 mt-3 break-all">
            Wallet: {profile.wallet_address}
          </p>
        )}

        {editingProfile && (
          <form onSubmit={saveProfile} className="mt-5 space-y-3">
            <input
              required
              type="text"
              value={profileForm.full_name}
              onChange={e =>
                setProfileForm({ ...profileForm, full_name: e.target.value })
              }
              placeholder="Full name"
              className="w-full border rounded-lg p-3"
            />

            <input
              type="email"
              value={profileForm.email}
              onChange={e =>
                setProfileForm({ ...profileForm, email: e.target.value })
              }
              placeholder="Email address"
              className="w-full border rounded-lg p-3"
            />

            <div className="flex gap-2">
              <button
                type="submit"
                className="bg-indigo-600 text-white rounded-lg px-4 py-2"
              >
                Save Changes
              </button>
              <button
                type="button"
                onClick={() => setEditingProfile(false)}
                className="border rounded-lg px-4 py-2"
              >
                Cancel
              </button>
            </div>
          </form>
        )}
      </div>

      <div className="grid md:grid-cols-2 gap-5">

        <QuickCreate
          title="Create a team"
          endpoint="/teams/"
          fields={["name", "description"]}
          onDone={load}
        />

        <QuickCreate
          title="Create a project"
          endpoint="/projects/"
          fields={["team", "name", "description", "due_date"]}
          teams={teams}
          onDone={load}
        />

      </div>

    </Shell>
  );
}

// ==========================================
// TEAM AND PROJECT QUICK CREATION
// ==========================================

function QuickCreate({
  title,
  endpoint,
  fields,
  teams = [],
  onDone
}) {
  const [data, setData] = useState({});
  const [msg, setMsg] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    setMsg("");

    try {
      const payload = { ...data };

      Object.keys(payload).forEach(key => {
        if (payload[key] === "") {
          delete payload[key];
        }
      });

      await api.post(endpoint, payload);

      setData({});
      setMsg("Created successfully.");

      onDone();
    } catch (error) {
      setMsg(
        JSON.stringify(
          error.response?.data || "Could not create."
        )
      );
    }
  };

  return (
    <form
      onSubmit={submit}
      className="bg-white border rounded-2xl p-6 space-y-3"
    >

      <h2 className="font-bold text-lg">{title}</h2>

      {fields.map(field =>
        field === "team" ? (

          <select
            key={field}
            required
            value={data[field] || ""}
            onChange={e =>
              setData({
                ...data,
                [field]: e.target.value
              })
            }
            className="w-full border rounded-lg p-3"
          >
            <option value="">Select team</option>

            {teams.map(team => (
              <option key={team.id} value={team.id}>
                {team.name}
              </option>
            ))}

          </select>

        ) : (

          <input
            key={field}
            required={field !== "description"}
            type={field === "due_date" ? "date" : "text"}
            placeholder={field.replace("_", " ")}
            value={data[field] || ""}
            onChange={e =>
              setData({
                ...data,
                [field]: e.target.value
              })
            }
            className="w-full border rounded-lg p-3"
          />

        )
      )}

      {msg && (
        <p className="text-sm text-slate-600 break-words">
          {msg}
        </p>
      )}

      <button
        type="submit"
        className="bg-indigo-600 text-white rounded-lg px-4 py-2 flex items-center gap-2"
      >
        <Plus size={16} />
        Create
      </button>

    </form>
  );
}

// ==========================================
// TEAM MANAGEMENT
// ==========================================


function Teams() {
  const [teams, setTeams] = useState([]);
  const [channels, setChannels] = useState({});
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [invite, setInvite] = useState({});

  const load = async () => {
    try {
      const response = await api.get("/teams/");
      const teamList = Array.isArray(response.data)
        ? response.data
        : response.data.results || [];

      setTeams(teamList);

      const channelResults = await Promise.all(
        teamList.map(async (team) => {
          try {
            const res = await api.get(`/teams/${team.id}/channels/`);
            return [team.id, res.data];
          } catch (error) {
            console.error(`Channels failed for team ${team.id}:`, error);
            return [team.id, []];
          }
        })
      );

      setChannels(Object.fromEntries(channelResults));
    } catch (error) {
      console.error("Teams loading error:", error.response?.data || error);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const create = async (e) => {
    e.preventDefault();

    try {
      await api.post("/teams/", { name, description });
      setName("");
      setDescription("");
      await load();
    } catch (error) {
      alert(JSON.stringify(error.response?.data || error.message));
    }
  };

  const add = async (id) => {
    try {
      await api.post(`/teams/${id}/members/`, {
        username: invite[id]
      });

      setInvite({ ...invite, [id]: "" });
      await load();
      alert("Member added successfully.");
    } catch (error) {
      alert(JSON.stringify(error.response?.data || error.message));
    }
  };

  const removeMember = async (teamId, userId, username) => {
    if (!window.confirm(`Remove ${username} from this team?`)) return;

    try {
      await api.delete(`/teams/${teamId}/members/${userId}/`);
      await load();
      alert(`${username} removed successfully.`);
    } catch (error) {
      alert(JSON.stringify(error.response?.data || error.message));
    }
  };

  const channel = async (id) => {
    const channelName = prompt("Channel name?");
    if (!channelName) return;

    try {
      await api.post(`/teams/${id}/channels/`, {
        name: channelName
      });

      await load();
      alert("Channel created successfully.");
    } catch (error) {
      alert(JSON.stringify(error.response?.data || error.message));
    }
  };

  return (
    <Shell active="/teams">
      <h1 className="text-3xl font-bold mb-6">Teams</h1>

      <form
        onSubmit={create}
        className="bg-white border rounded-2xl p-5 mb-6 flex flex-wrap gap-3"
      >
        <input
          required
          placeholder="Team name"
          value={name}
          onChange={e => setName(e.target.value)}
          className="border rounded-lg p-3 flex-1"
        />

        <input
          placeholder="Description"
          value={description}
          onChange={e => setDescription(e.target.value)}
          className="border rounded-lg p-3 flex-1"
        />

        <button className="bg-indigo-600 text-white rounded-lg px-5">
          Create team
        </button>
      </form>

      <div className="grid md:grid-cols-2 gap-4">
        {teams.map(team => (
          <div
            key={team.id}
            className="bg-white border rounded-2xl p-5"
          >
            <h2 className="font-bold text-xl">{team.name}</h2>

            <p className="text-slate-500">{team.description}</p>

            <p className="text-sm mt-3">
              Owner: {team.owner_name}
            </p>

            <div className="mt-3">
              <p className="text-sm font-semibold mb-2">Members</p>

              <div className="space-y-2">
                {(team.members || []).map(member => (
                  <div
                    key={member.id}
                    className="flex items-center justify-between gap-3 border rounded-lg p-2"
                  >
                    <span className="text-sm">
                      {member.username}
                      {member.role === "owner" && " (Owner)"}
                    </span>

                    {member.role !== "owner" && (
                      <button
                        type="button"
                        onClick={() =>
                          removeMember(team.id, member.user_id, member.username)
                        }
                        className="text-red-600 border border-red-200 rounded-lg px-3 py-1 text-sm hover:bg-red-50"
                      >
                        Remove
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-5">
              <h3 className="font-semibold mb-2">Channels</h3>

              {(channels[team.id] || []).length > 0 ? (
                <div className="space-y-2">
                  {channels[team.id].map(ch => (
                    <div
                      key={ch.id}
                      className="border rounded-lg p-3"
                    >
                      <p className="font-medium"># {ch.name}</p>
                      {ch.description && (
                        <p className="text-sm text-slate-500">
                          {ch.description}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-400">
                  No channels created yet.
                </p>
              )}
            </div>

            <div className="flex flex-wrap gap-2 mt-4">
              <input
                placeholder="Username to add"
                value={invite[team.id] || ""}
                onChange={e =>
                  setInvite({ ...invite, [team.id]: e.target.value })
                }
                className="border rounded-lg p-2 min-w-0 flex-1"
              />

              <button
                type="button"
                onClick={() => add(team.id)}
                className="bg-slate-900 text-white rounded-lg px-3"
              >
                Add
              </button>

              <button
                type="button"
                onClick={() => channel(team.id)}
                className="border rounded-lg px-3"
              >
                + Channel
              </button>
            </div>
          </div>
        ))}
      </div>
    </Shell>
  );
}



// ==========================================
// PROJECT, TASK AND MILESTONE MANAGEMENT
// ==========================================

function Projects() {
  const [projects, setProjects] = useState([]);
  const [teams, setTeams] = useState([]);

  const load = async () => {
    try {
      const [projectResponse, teamResponse] = await Promise.all([
        api.get("/projects/"),
        api.get("/teams/")
      ]);

      setProjects(
        Array.isArray(projectResponse.data)
          ? projectResponse.data
          : projectResponse.data.results || []
      );

      setTeams(
        Array.isArray(teamResponse.data)
          ? teamResponse.data
          : teamResponse.data.results || []
      );
    } catch (error) {
      console.error("Loading error:", error.response?.data || error);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const addTask = async (project) => {
    const title = prompt("Task title?");
    if (!title) return;

    const deadline = prompt("Deadline (YYYY-MM-DD), optional:") || null;

    try {
      await api.post("/tasks/", {
        project: project.id,
        title,
        deadline,
        status: "todo"
      });

      load();
    } catch (error) {
      alert(JSON.stringify(error.response?.data || error.message));
    }
  };

  const assignTask = async (task, userId) => {
    try {
      await api.patch(`/tasks/${task.id}/`, {
        assigned_to: userId ? Number(userId) : null
      });

      await load();
      alert("Task assignment updated successfully.");
    } catch (error) {
      alert(JSON.stringify(error.response?.data || error.message));
    }
  };

  const addMilestone = async (project) => {
    const title = prompt("Milestone title?");
    if (!title) return;

    try {
      await api.post("/milestones/", {
        project: project.id,
        title,
        status: "pending"
      });

      load();
    } catch (error) {
      alert(JSON.stringify(error.response?.data || error.message));
    }
  };

  const updateTaskStatus = async (task, newStatus) => {
    try {
      await api.patch(`/tasks/${task.id}/`, {
        status: newStatus
      });
      load();
    } catch (error) {
      alert(JSON.stringify(error.response?.data || error.message));
    }
  };

  const updateMilestoneStatus = async (milestone, newStatus) => {
    try {
      await api.patch(`/milestones/${milestone.id}/`, {
        status: newStatus
      });
      load();
    } catch (error) {
      alert(JSON.stringify(error.response?.data || error.message));
    }
  };

  return (
    <Shell active="/projects">
      <h1 className="text-3xl font-bold mb-6">
        Projects & Delivery
      </h1>

      <div className="mb-8">
        <QuickCreate
          title="Create a new project"
          endpoint="/projects/"
          fields={["team", "name", "description", "due_date"]}
          teams={teams}
          onDone={load}
        />
      </div>

      <h2 className="text-xl font-bold mb-4">
        Your Projects ({projects.length})
      </h2>

      <div className="space-y-5">
        {projects.map(project => {
          const projectTeam = teams.find(
            team => team.id === project.team
          );

          const members = projectTeam?.members || [];

          return (
            <div
              key={project.id}
              className="bg-white border rounded-2xl p-6"
            >
              <div className="flex justify-between gap-3 flex-wrap">
                <div>
                  <h2 className="font-bold text-xl">
                    {project.name}
                  </h2>

                  <p className="text-slate-500">
                    {project.description}
                  </p>

                  <p className="text-xs text-slate-400 mt-2">
                    Team #{project.team} · Due {project.due_date || "Not set"}
                  </p>
                </div>

                <div className="flex gap-2">
                  <button
                    onClick={() => addTask(project)}
                    className="bg-indigo-600 text-white rounded-lg px-3 py-2"
                  >
                    + Task
                  </button>

                  <button
                    onClick={() => addMilestone(project)}
                    className="border rounded-lg px-3 py-2"
                  >
                    + Milestone
                  </button>
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-4 mt-5">
                <section>
                  <h3 className="font-semibold mb-2">Tasks</h3>

                  {(project.tasks || []).map(task => (
                    <div
                      key={task.id}
                      className="border rounded-lg p-3 mb-2"
                    >
                      <div className="font-medium">
                        {task.title}
                      </div>

                      <div className="text-xs text-slate-500 mb-2">
                        Assigned: {task.assigned_username || "Unassigned"}
                        {" · "}
                        Due: {task.deadline || "—"}
                      </div>

                      <div className="flex flex-wrap gap-2 items-center">
                        <select
                          value={task.assigned_to || ""}
                          onChange={e =>
                            assignTask(task, e.target.value)
                          }
                          className="border rounded-lg p-2 text-sm"
                        >
                          <option value="">Unassigned</option>

                          {members.map(member => (
                            <option
                              key={member.user_id}
                              value={member.user_id}
                            >
                              {member.username}
                            </option>
                          ))}
                        </select>

                        <select
                          value={task.status}
                          onChange={e =>
                            updateTaskStatus(task, e.target.value)
                          }
                          className="border rounded-lg p-2 text-sm"
                        >
                          <option value="todo">To do</option>
                          <option value="in_progress">In progress</option>
                          <option value="done">Done</option>
                        </select>
                      </div>
                    </div>
                  ))}
                </section>

                <section>
                  <h3 className="font-semibold mb-2">Milestones</h3>

                  {(project.milestones || []).map(milestone => (
                    <div
                      key={milestone.id}
                      className="border rounded-lg p-3 mb-2"
                    >
                      <div className="font-medium">
                        {milestone.title}
                      </div>

                      <div className="text-xs text-slate-500">
                        {milestone.due_date || "No deadline"}
                        {" · "}
                        {milestone.status}
                      </div>

                      <select
                        value={milestone.status}
                        onChange={e =>
                          updateMilestoneStatus(
                            milestone,
                            e.target.value
                          )
                        }
                        className="border rounded p-1 text-sm mt-2"
                      >
                        <option value="pending">Pending</option>
                        <option value="in_progress">In progress</option>
                        <option value="completed">Completed</option>
                      </select>
                    </div>
                  ))}
                </section>
              </div>
            </div>
          );
        })}
      </div>
    </Shell>
  );
}


// ==========================================
// PROTECTED ROUTE
// ==========================================

function Guard({ children }) {
  const token = localStorage.getItem("access");

  return token
    ? children
    : <Navigate to="/login" replace />;
}

// ==========================================
// MAIN APPLICATION ROUTES
// ==========================================

export default function App() {
  return (
    <BrowserRouter>

      <Routes>

        <Route
          path="/login"
          element={<Auth mode="login" />}
        />

        <Route
          path="/register"
          element={<Auth mode="register" />}
        />

        <Route
          path="/"
          element={
            <Guard>
              <Dashboard />
            </Guard>
          }
        />

        <Route
          path="/teams"
          element={
            <Guard>
              <Teams />
            </Guard>
          }
        />

        <Route
          path="/projects"
          element={
            <Guard>
              <Projects />
            </Guard>
          }
        />
        <Route
          path="/artifacts"
          element={
            <Guard>
              <div className="min-h-screen bg-slate-50">
                <Shell active="/artifacts">
                  <Artifacts />
                </Shell>
              </div>
            </Guard>
          }
        />
        <Route
          path="/chat"
          element={
            <Guard>
              <Chat Shell={Shell} />
            </Guard>
          }
        />

        <Route
          path="*"
          element={<Navigate to="/" replace />}
        />

      </Routes>

    </BrowserRouter>
  );
}
