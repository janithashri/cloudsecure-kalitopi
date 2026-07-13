import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <nav className="bg-slate-800 text-white shadow">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4">
        <div className="flex items-center gap-6">
          <Link to="/dashboard" className="text-lg font-semibold">
            ☁ CloudSecure
          </Link>
          <Link to="/dashboard" className="text-slate-300 hover:text-white">
            Dashboard
          </Link>
          <Link to="/providers" className="text-slate-300 hover:text-white">
            Providers
          </Link>
          <Link to="/findings" className="text-slate-300 hover:text-white">
            Findings
          </Link>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-sm text-slate-300">{user?.email || user?.username || ""}</span>
          <button
            type="button"
            onClick={handleLogout}
            className="rounded bg-slate-600 px-3 py-1.5 text-sm hover:bg-slate-500"
          >
            Logout
          </button>
        </div>
      </div>
    </nav>
  );
}
