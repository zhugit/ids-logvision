import axios from "axios";

export const API_BASE = "http://localhost:8000";

export const http = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
});

http.interceptors.response.use(
  (res) => res,
  (err) => {
    console.error("[HTTP ERROR]", err?.message || err);
    throw err;
  }
);
