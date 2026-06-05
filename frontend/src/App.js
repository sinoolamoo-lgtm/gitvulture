import { useEffect, useState } from "react";
import "@/index.css";
import "@/App.css";
import { BrowserRouter, Routes, Route, Link, useNavigate, useParams } from "react-router-dom";
import { Toaster } from "sonner";
import Dashboard from "@/pages/Dashboard";
import ScanDetails from "@/pages/ScanDetails";
import { Crosshair, Terminal, Cpu, Activity, BookOpen } from "lucide-react";

function Header() {
  return (
    <header className="header-glass sticky top-0 z-50">
      <div className="max-w-[1600px] mx-auto px-6 py-3 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-3" data-testid="header-logo">
          <div className="w-8 h-8 border border-white flex items-center justify-center">
            <Crosshair size={18} className="text-white" />
          </div>
          <div>
            <div className="font-display text-xl font-extrabold tracking-tight uppercase leading-none">
              Git<span className="text-[#00FF41]">Vulture</span>
            </div>
            <div className="font-mono text-[10px] text-[#6E7681] tracking-[0.2em] uppercase mt-0.5">
              .git exposure exploitation
            </div>
          </div>
        </Link>
        <nav className="flex items-center gap-1">
          <Link to="/" className="btn-ghost" data-testid="nav-scans">
            <Activity size={12} className="inline mr-2 -mt-0.5" /> Scans
          </Link>
          <a
            href="https://github.com/arthaud/git-dumper"
            target="_blank"
            rel="noreferrer"
            className="btn-ghost"
            data-testid="nav-docs"
          >
            <BookOpen size={12} className="inline mr-2 -mt-0.5" /> Docs
          </a>
        </nav>
      </div>
    </header>
  );
}

function Footer() {
  return (
    <footer className="border-t border-[#1f1f1f] mt-16">
      <div className="max-w-[1600px] mx-auto px-6 py-4 flex items-center justify-between font-mono text-[10px] tracking-[0.18em] uppercase text-[#484F58]">
        <span>GitVulture v1.0 · standalone CLI &amp; Web</span>
        <span>For authorized testing only · 2026</span>
      </div>
    </footer>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="bg-grid min-h-screen">
        <div className="scan-line" />
        <Header />
        <main className="max-w-[1600px] mx-auto px-6 py-8 relative z-10">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan/:id" element={<ScanDetails />} />
          </Routes>
        </main>
        <Footer />
      </div>
      <Toaster theme="dark" position="bottom-right" closeButton />
    </BrowserRouter>
  );
}
