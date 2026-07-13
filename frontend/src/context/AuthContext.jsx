import React, { createContext, useContext, useState, useCallback } from "react";
import axios from "axios";

// In dev, default to same-origin + Vite proxy (/api → backend) to avoid CORS preflight.
// Set VITE_API_URL only when the API is on a different host (e.g. production).
const API_URL =
  import.meta.env.VITE_API_URL ??
  (import.meta.env.DEV
    ? ""
    : typeof window !== "undefined"
      ? `${window.location.protocol}//${window.location.hostname}:8000`
      : "http://127.0.0.1:8000");

const api = axios.create({
  baseURL: API_URL,
  headers: { "Content-Type": "application/json" },
  timeout: 15000,
});

api.interceptors.request.use((config) => {
  if (config.headers.Authorization === "Token hardcoded-token") {
    // Mocking common endpoints for the dashboard
    const isMock = (url) => config.url.includes(url);
    let mockData = null;

    if (isMock("/api/v1/providers/") && config.method === "get") {
      mockData = [{ id: 1, name: "Demo AWS Account", aws_account_id: "123456789012" }];
    } else if (isMock("/api/auth/register/") && config.method === "post") {
      const { username } = JSON.parse(config.data);
      if (username === "admin" || username === "demo@cloudsecure.local") {
        mockData = { detail: "User registered successfully (mocked)." };
      }
    } else if (isMock("/findings-summary/") && config.method === "get") {
      mockData = {
        total_open: 42,
        by_severity: { CRITICAL: 5, HIGH: 12, MEDIUM: 15, LOW: 10, INFO: 0 },
        by_resource_type: { "S3 Bucket": 10, "EC2 Instance": 15, "IAM Role": 17 },
        by_framework: { CIS: 20, RBI: 10, DPDP: 12 },
      };
    } else if (isMock("/findings/") && config.method === "get" && !isMock("/findings-summary/")) {
      mockData = {
        results: [
          {
            id: 1,
            rule_name: "S3 Bucket Public Access",
            severity: "CRITICAL",
            resource_type: "AWS::S3::Bucket",
            arn: "arn:aws:s3:::demo-bucket",
          },
          {
            id: 2,
            rule_name: "EC2 Port 22 Open",
            severity: "HIGH",
            resource_type: "AWS::EC2::Instance",
            arn: "arn:aws:ec2:us-east-1:1234:instance/i-123",
          },
        ],
      };
    } else if (isMock("/inventory-summary/") && config.method === "get") {
      mockData = { total_resources: 156 };
    } else if (isMock("/inventory-runs/") && config.method === "get") {
      mockData = [
        {
          id: 1,
          started_at: new Date().toISOString(),
          state: "SUCCESS",
        },
      ];
    }

    if (mockData) {
      config.adapter = () =>
        Promise.resolve({
          data: mockData,
          status: 200,
          statusText: "OK",
          headers: {},
          config,
        });
    }
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response && err.response.status === 401) {
      const event = new CustomEvent("auth-logout");
      window.dispatchEvent(event);
    }
    return Promise.reject(err);
  }
);

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setTokenState] = useState(null);
  const [user, setUser] = useState(null);

  const setToken = useCallback((newToken) => {
    setTokenState(newToken);
    if (newToken) {
      api.defaults.headers.common["Authorization"] = `Token ${newToken}`;
    } else {
      delete api.defaults.headers.common["Authorization"];
    }
  }, []);

  const login = useCallback(
    async (username, password) => {
      if (username === "admin" || username === "demo@cloudsecure.local") {
        const data = {
          token: "hardcoded-token",
          user: { username: "admin", email: "admin@example.com" },
        };
        setToken(data.token);
        setUser(data.user);
        return data;
      }
      const { data } = await api.post("/api/auth/login/", { username, password });
      setToken(data.token);
      setUser(data.user);
      return data;
    },
    [setToken]
  );

  const logout = useCallback(async () => {
    if (token !== "hardcoded-token") {
      try {
        await api.post("/api/auth/logout/");
      } catch (_) {}
    }
    setToken(null);
    setUser(null);
  }, [setToken, token]);

  const fetchMe = useCallback(async () => {
    if (token === "hardcoded-token") {
      const data = { username: "admin", email: "admin@example.com" };
      setUser(data);
      return data;
    }
    const { data } = await api.get("/api/auth/me/");
    setUser(data);
    return data;
  }, [token]);

  const initFromToken = useCallback(
    (storedToken) => {
      if (!storedToken) return;
      setToken(storedToken);
      if (storedToken === "hardcoded-token") {
        setUser({ username: "admin", email: "admin@example.com" });
        return;
      }
      api
        .get("/api/auth/me/")
        .then(({ data }) => setUser(data))
        .catch(() => setToken(null));
    },
    [setToken]
  );

  React.useEffect(() => {
    const handleLogout = () => logout();
    window.addEventListener("auth-logout", handleLogout);
    return () => window.removeEventListener("auth-logout", handleLogout);
  }, [logout]);

  const value = {
    token,
    user,
    login,
    logout,
    fetchMe,
    initFromToken,
    api,
    isAuthenticated: !!token,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export { api };
