import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const API = `${BACKEND_URL}/api`;

export const api = axios.create({
  baseURL: API,
  headers: { "Content-Type": "application/json" },
});

export async function createScan(payload) {
  const { data } = await api.post("/scans", payload);
  return data;
}

export async function listScans() {
  const { data } = await api.get("/scans");
  return data;
}

export async function getScan(id) {
  const { data } = await api.get(`/scans/${id}`);
  return data;
}

export async function deleteScan(id) {
  const { data } = await api.delete(`/scans/${id}`);
  return data;
}

export function eventSource(id) {
  return new EventSource(`${API}/scans/${id}/events`);
}

export function reportUrl(id) {
  return `${API}/scans/${id}/report`;
}

export function dumpUrl(id) {
  return `${API}/scans/${id}/dump`;
}

export function forgeryUrl(id) {
  return `${API}/scans/${id}/forgery`;
}
