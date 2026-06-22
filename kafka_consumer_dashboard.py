import selectors
from selectors import SelectorKey

# Workaround for selectors.py raising ValueError instead of KeyError on Python 3.12+ (e.g. invalid file descriptors)
# We apply the patch to both BaseSelector and _BaseSelectorImpl to handle subclasses overriding unregister.
for selector_cls in [selectors.BaseSelector, getattr(selectors, "_BaseSelectorImpl", None)]:
    if selector_cls is not None and hasattr(selector_cls, "unregister"):
        _orig_unregister = selector_cls.unregister
        def make_safe_unregister(orig_unreg):
            def _safe_unregister(self, fileobj):
                try:
                    return orig_unreg(self, fileobj)
                except (ValueError, KeyError):
                    # If it failed (e.g., closed socket with fd=-1), search for it by object identity in registered keys
                    found_fd = None
                    if hasattr(self, "_fd_to_key"):
                        for fd, key in list(self._fd_to_key.items()):
                            if key.fileobj is fileobj:
                                found_fd = fd
                                break
                    if found_fd is not None:
                        try:
                            return orig_unreg(self, found_fd)
                        except (ValueError, KeyError):
                            pass
                    # Fallback if not found: return a dummy SelectorKey to prevent unhandled KeyError crashes in kafka-python
                    return SelectorKey(fileobj, -1, 0, None)
            return _safe_unregister
        selector_cls.unregister = make_safe_unregister(_orig_unregister)

import json
import time
import gc
from collections import defaultdict
from pathlib import Path
from datetime import datetime
import psutil
from kafka import KafkaConsumer

# Create reports directory if missing
Path("reports").mkdir(exist_ok=True)

# Path definitions
dashboard_file = Path("dashboard.html")
data_file = Path("dashboard_data.js")
history_file = Path("reports/dashboard_history.jsonl")

# Capped in-memory state for RAM optimization
file_logs = defaultdict(list)
latest_events = []
seen_hashes = set()
seen_hashes_list = []  # Maintain order to cap seen_hashes size

# Global stats counter
total_logs_count = 0

def write_static_html():
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Compliance & Configuration Posture</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-main: #030712;
            --bg-panel: rgba(10, 15, 30, 0.7);
            --bg-card: #070a13;
            --border-color: rgba(255, 255, 255, 0.05);
            
            --color-total: #00f2fe;
            --color-files: #38bdf8;
            --color-critical: #ef4444;
            --color-warning: #f59e0b;
            --color-investigative: #a855f7;
            --color-info: #10b981;
            --color-statistics: #3b82f6;
            
            --glow-total: rgba(0, 242, 254, 0.2);
            --glow-files: rgba(56, 189, 248, 0.2);
            --glow-critical: rgba(239, 68, 68, 0.35);
            --glow-warning: rgba(245, 158, 11, 0.3);
            --glow-investigative: rgba(168, 85, 247, 0.3);
            --glow-info: rgba(16, 185, 129, 0.3);
            --glow-statistics: rgba(59, 130, 246, 0.2);
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-main);
            color: #f3f4f6;
            margin: 0;
            padding: 20px;
            background-image: 
                radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.05) 0px, transparent 50%),
                radial-gradient(at 50% 0%, rgba(139, 92, 246, 0.03) 0px, transparent 50%),
                radial-gradient(at 100% 0%, rgba(236, 72, 153, 0.04) 0px, transparent 50%);
            background-attachment: fixed;
        }

        .dashboard-container {
            max-width: 1700px;
            margin: 0 auto;
        }

        @keyframes pulse {
            0% { transform: scale(1); opacity: 0.8; }
            50% { transform: scale(1.05); opacity: 1; }
            100% { transform: scale(1); opacity: 0.8; }
        }

        .pulse-active {
            animation: pulse 2s infinite ease-in-out;
        }

        .header-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding: 20px 30px;
            background: var(--bg-panel);
            border-radius: 16px;
            border: 1px solid var(--border-color);
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.4);
        }

        .header-container h1 {
            margin: 0;
            font-size: 26px;
            font-weight: 900;
            letter-spacing: 1px;
            text-transform: uppercase;
            background: linear-gradient(90deg, #00f2fe, #4facfe, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .header-container h1::before {
            content: '🛡️';
        }

        .status-panel {
            display: flex;
            gap: 24px;
            align-items: center;
            background: rgba(17, 24, 39, 0.8);
            padding: 12px 24px;
            border-radius: 30px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }

        .status-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }

        .status-dot.active {
            background-color: #10b981;
            box-shadow: 0 0 12px #10b981;
        }

        .status-dot.idle {
            background-color: #f59e0b;
            box-shadow: 0 0 12px #f59e0b;
        }

        .status-label {
            color: #9ca3af;
        }

        .status-val {
            font-weight: 600;
        }

        .text-active {
            color: #10b981;
        }

        .text-idle {
            color: #f59e0b;
        }

        .clock {
            border-left: 1px solid rgba(255, 255, 255, 0.15);
            padding-left: 15px;
        }

        #live-clock {
            font-family: 'JetBrains Mono', monospace;
            color: #38bdf8;
            font-weight: 700;
        }

        /* Metrics grid with liquid borders */
        .metrics-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 16px;
            margin-bottom: 25px;
        }

        .metric-card {
            position: relative;
            background: var(--bg-panel);
            border-radius: 12px;
            padding: 20px;
            overflow: hidden;
            transition: all 0.4s cubic-bezier(0.25, 0.8, 0.25, 1);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-color);
            z-index: 1;
        }

        /* Conic gradient rotating border (liquid hover effect) */
        .metric-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: conic-gradient(
                transparent,
                var(--card-accent, #38bdf8),
                transparent 20%,
                var(--card-accent-alt, #818cf8),
                transparent 50%,
                var(--card-accent, #38bdf8),
                transparent 70%
            );
            animation: rotate-liquid 6s linear infinite;
            opacity: 0;
            transition: opacity 0.4s ease;
            z-index: -2;
            pointer-events: none;
        }

        .metric-card::after {
            content: '';
            position: absolute;
            inset: 1.5px;
            background: var(--bg-card);
            border-radius: 10.5px;
            z-index: -1;
        }

        .metric-card:hover::before {
            opacity: 1;
        }

        .metric-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 25px var(--card-glow, rgba(56, 189, 248, 0.15));
            border-color: transparent;
        }

        .metric-card h3 {
            margin: 0;
            color: #9ca3af;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 700;
        }

        .metric-card p {
            margin: 12px 0 0 0;
            font-size: 32px;
            font-weight: 800;
            color: #ffffff;
            font-family: 'JetBrains Mono', monospace;
            line-height: 1;
        }

        /* Card custom property overrides */
        .card-total {
            --card-accent: var(--color-total);
            --card-accent-alt: #4facfe;
            --card-glow: var(--glow-total);
        }
        .card-files {
            --card-accent: var(--color-files);
            --card-accent-alt: #818cf8;
            --card-glow: var(--glow-files);
        }
        .card-critical {
            --card-accent: var(--color-critical);
            --card-accent-alt: #ef4444;
            --card-glow: var(--glow-critical);
        }
        .card-warning {
            --card-accent: var(--color-warning);
            --card-accent-alt: #fbbf24;
            --card-glow: var(--glow-warning);
        }
        .card-investigative {
            --card-accent: var(--color-investigative);
            --card-accent-alt: #c084fc;
            --card-glow: var(--glow-investigative);
        }
        .card-info {
            --card-accent: var(--color-info);
            --card-accent-alt: #34d399;
            --card-glow: var(--glow-info);
        }
        .card-statistics {
            --card-accent: var(--color-statistics);
            --card-accent-alt: #60a5fa;
            --card-glow: var(--glow-statistics);
        }
        .card-device, .card-ip {
            --card-accent: #9ca3af;
            --card-accent-alt: #cbd5e1;
            --card-glow: rgba(255, 255, 255, 0.08);
        }

        @keyframes rotate-liquid {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        /* Layout split */
        .main-layout {
            display: grid;
            grid-template-columns: 380px 1fr;
            gap: 24px;
        }

        /* Sidebar styling with left glow border */
        .sidebar {
            background: var(--bg-panel);
            border-radius: 16px;
            border: 1px solid var(--border-color);
            border-left: 3px solid var(--color-files);
            padding: 24px 20px;
            max-height: 850px;
            overflow-y: auto;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.4), 0 0 15px var(--glow-files);
            backdrop-filter: blur(12px);
        }

        .sidebar h2 {
            margin-top: 0;
            margin-bottom: 24px;
            font-size: 16px;
            font-weight: 800;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: #e5e7eb;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .sidebar::-webkit-scrollbar, .content::-webkit-scrollbar {
            width: 6px;
        }
        .sidebar::-webkit-scrollbar-thumb, .content::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
        }

        /* Sidebar Details accordion style */
        details {
            margin-bottom: 12px;
            background: rgba(17, 24, 39, 0.4);
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            overflow: hidden;
            transition: all 0.3s ease;
        }

        details[open] {
            border-color: rgba(56, 189, 248, 0.3);
            box-shadow: 0 4px 15px rgba(56, 189, 248, 0.1);
        }

        summary {
            padding: 14px 16px;
            font-weight: 600;
            cursor: pointer;
            color: #38bdf8;
            outline: none;
            font-size: 13.5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(17, 24, 39, 0.6);
            user-select: none;
            transition: background-color 0.2s ease;
        }

        summary:hover {
            background: rgba(17, 24, 39, 0.9);
            color: #ffffff;
        }

        summary::-webkit-details-marker {
            display: none;
        }

        summary::after {
            content: '▶';
            font-size: 10px;
            transition: transform 0.2s ease;
            color: #9ca3af;
        }

        details[open] summary::after {
            transform: rotate(90deg);
            color: #38bdf8;
        }

        .logcard {
            background: #030712;
            padding: 12px;
            margin: 8px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.03);
            box-shadow: inset 0 2px 8px rgba(0,0,0,0.8);
        }

        pre {
            margin: 0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            overflow-x: auto;
            color: #cbd5e1;
        }

        /* Content Panel with left glow border */
        .content {
            background: var(--bg-panel);
            border-radius: 16px;
            border: 1px solid var(--border-color);
            border-left: 3px solid var(--color-investigative);
            padding: 24px;
            max-height: 850px;
            overflow-y: auto;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.4), 0 0 15px var(--glow-investigative);
            backdrop-filter: blur(12px);
        }

        .content h2 {
            margin-top: 0;
            margin-bottom: 24px;
            font-size: 16px;
            font-weight: 800;
        }
        /* Main View Navigation Tabs */
        .nav-tabs {
            display: flex;
            gap: 12px;
            margin-bottom: 24px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            padding-bottom: 12px;
        }

        .nav-tab {
            background: transparent;
            color: #9ca3af;
            border: none;
            font-family: inherit;
            font-size: 15px;
            font-weight: 800;
            cursor: pointer;
            padding: 8px 16px;
            border-bottom: 2px solid transparent;
            letter-spacing: 1px;
            text-transform: uppercase;
            transition: all 0.3s ease;
        }

        .nav-tab:hover {
            color: #ffffff;
        }

        .nav-tab.active {
            color: #00f2fe;
            border-bottom-color: #00f2fe;
            text-shadow: 0 0 10px rgba(0, 242, 254, 0.4);
        }

        /* Tabs styled with sliding liquid hover */
        .tabs {
            margin-bottom: 20px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .tabs button {
            position: relative;
            background: rgba(17, 24, 39, 0.6);
            color: #d1d5db;
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 10px 20px;
            cursor: pointer;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.3s ease;
            overflow: hidden;
            z-index: 1;
            font-family: inherit;
            outline: none;
            box-sizing: border-box;
        }

        .tabs button::before {
            content: '';
            position: absolute;
            inset: 0;
            background: var(--tab-gradient, linear-gradient(135deg, #00f2fe 0%, #4facfe 100%));
            transform: scaleX(0);
            transform-origin: left;
            transition: transform 0.35s cubic-bezier(0.25, 0.8, 0.25, 1);
            z-index: -1;
        }

        .tabs button:hover::before, .tabs button.active::before {
            transform: scaleX(1);
        }

        .tabs button:hover, .tabs button.active {
            color: #030712 !important;
            border-color: transparent;
            box-shadow: 0 0 15px var(--tab-glow, rgba(56, 189, 248, 0.4));
            font-weight: 700;
        }

        /* Tab button severity colors */
        .tabs button[data-severity="ALL"] { --tab-gradient: linear-gradient(135deg, #38bdf8, #818cf8); --tab-glow: rgba(56, 189, 248, 0.4); }
        .tabs button[data-severity="CRITICAL"] { --tab-gradient: linear-gradient(135deg, #ff4d4d, #f43f5e); --tab-glow: rgba(239, 68, 68, 0.5); }
        .tabs button[data-severity="WARNING"] { --tab-gradient: linear-gradient(135deg, #ff9500, #fbbf24); --tab-glow: rgba(245, 158, 11, 0.5); }
        .tabs button[data-severity="INVESTIGATE"] { --tab-gradient: linear-gradient(135deg, #b76eff, #a855f7); --tab-glow: rgba(168, 85, 247, 0.5); }
        .tabs button[data-severity="INFO"] { --tab-gradient: linear-gradient(135deg, #00e676, #10b981); --tab-glow: rgba(16, 185, 129, 0.5); }
        .tabs button[data-severity="STATISTICAL"] { --tab-gradient: linear-gradient(135deg, #3b82f6, #60a5fa); --tab-glow: rgba(59, 130, 246, 0.5); }

        /* Search bar styling */
        .search-container {
            position: relative;
            margin-bottom: 24px;
        }

        input[type="text"] {
            width: 100%;
            padding: 14px 24px;
            background: rgba(17, 24, 39, 0.6);
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 30px;
            outline: none;
            font-family: inherit;
            font-size: 14px;
            transition: all 0.3s ease;
            box-sizing: border-box;
        }

        input[type="text"]:focus {
            border-color: #00f2fe;
            box-shadow: 0 0 15px rgba(0, 242, 254, 0.25);
            background: rgba(17, 24, 39, 0.85);
        }

        /* Cyber table */
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th, td {
            padding: 14px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 13.5px;
        }

        th {
            background-color: rgba(15, 23, 42, 0.9);
            color: #38bdf8;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 1.5px;
            border-bottom: 2px solid rgba(56, 189, 248, 0.2);
        }

        tr {
            transition: background-color 0.2s ease;
        }

        tr:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }

        /* Severity badge styling */
        .severity-critical {
            color: #ff4d4d;
            font-weight: 800;
            text-shadow: 0 0 12px rgba(239, 68, 68, 0.45);
        }

        .severity-warning {
            color: #ff9500;
            font-weight: 800;
            text-shadow: 0 0 12px rgba(245, 158, 11, 0.45);
        }

        .severity-investigate {
            color: #b76eff;
            font-weight: 800;
            text-shadow: 0 0 12px rgba(168, 85, 247, 0.45);
        }

        .severity-info {
            color: #00e676;
            font-weight: 800;
            text-shadow: 0 0 12px rgba(16, 185, 129, 0.45);
        }

        .severity-statistical {
            color: #3b82f6;
            font-weight: 800;
            text-shadow: 0 0 12px rgba(59, 130, 246, 0.45);
        }

        /* Progress bars */
        .progress-bar {
            width: 100%;
            max-width: 100px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.03);
            height: 14px;
        }

        .progress-fill {
            height: 100%;
            text-align: center;
            font-size: 8.5px;
            color: white;
            line-height: 14px;
            font-weight: 800;
            transition: width 0.5s ease-in-out;
        }

        .info-fill { background: linear-gradient(90deg, #10b981, #059669); }
        .warning-fill { background: linear-gradient(90deg, #f59e0b, #d97706); }
        .investigate-fill { background: linear-gradient(90deg, #a855f7, #7c3aed); }
        .critical-fill { background: linear-gradient(90deg, #ef4444, #dc2626); }
        .statistical-fill { background: linear-gradient(90deg, #3b82f6, #2563eb); }

        /* Compliance report classes */
        .badge-pass { background: rgba(16, 185, 129, 0.12); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.25); }
        .badge-fail { background: rgba(239, 68, 68, 0.12); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.25); }
        .badge-error { background: rgba(239, 68, 68, 0.12); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.25); }
        .badge-manual-review { background: rgba(245, 158, 11, 0.12); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.25); }

        .status-pass { border-left: 3px solid #10b981 !important; }
        .status-fail { border-left: 3px solid #ef4444 !important; }
        .status-warning { border-left: 3px solid #f59e0b !important; }

        .details-row td {
            background: rgba(10, 15, 25, 0.85) !important;
        }

        tr.expanded td {
            border-bottom-color: transparent !important;
        }

        /* Horizontal scrolling framework selector */
        .framework-scroll-container {
            display: flex;
            gap: 12px;
            overflow-x: auto;
            padding: 10px 5px 15px 5px;
            margin-bottom: 20px;
            scroll-behavior: smooth;
            -webkit-overflow-scrolling: touch;
        }

        .framework-scroll-container::-webkit-scrollbar {
            height: 6px;
        }
        .framework-scroll-container::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.02);
            border-radius: 3px;
        }
        .framework-scroll-container::-webkit-scrollbar-thumb {
            background: rgba(56, 189, 248, 0.2);
            border-radius: 3px;
        }
        .framework-scroll-container::-webkit-scrollbar-thumb:hover {
            background: rgba(56, 189, 248, 0.4);
        }

        .framework-card-btn {
            flex: 0 0 auto;
            background: rgba(10, 15, 30, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 12px 20px;
            min-width: 140px;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
            text-align: left;
            position: relative;
            overflow: hidden;
            z-index: 1;
            color: #d1d5db;
            font-family: inherit;
            outline: none;
            box-sizing: border-box;
        }

        .framework-card-btn::before {
            content: '';
            position: absolute;
            inset: 0;
            background: var(--fw-gradient, linear-gradient(135deg, #00f2fe 0%, #4facfe 100%));
            transform: scaleX(0);
            transform-origin: left;
            transition: transform 0.35s cubic-bezier(0.25, 0.8, 0.25, 1);
            z-index: -1;
        }

        .framework-card-btn:hover::before, .framework-card-btn.active::before {
            transform: scaleX(1);
        }

        .framework-card-btn:hover, .framework-card-btn.active {
            color: #030712 !important;
            border-color: transparent;
            box-shadow: 0 0 15px var(--fw-glow, rgba(0, 242, 254, 0.3));
        }

        .framework-card-btn h4 {
            margin: 0;
            font-size: 14px;
            font-weight: 800;
            letter-spacing: 0.5px;
            color: #ffffff;
            transition: color 0.3s;
        }
        .framework-card-btn:hover h4, .framework-card-btn.active h4 {
            color: #030712;
        }

        .framework-card-btn span {
            display: block;
            margin-top: 4px;
            font-size: 11px;
            color: #9ca3af;
            font-weight: 600;
            transition: color 0.3s;
        }
        .framework-card-btn:hover span, .framework-card-btn.active span {
            color: rgba(3, 7, 18, 0.7);
        }

        .framework-card-btn[data-framework="ALL"] { --fw-gradient: linear-gradient(135deg, #e5e7eb, #9ca3af); --fw-glow: rgba(255, 255, 255, 0.2); }
        .framework-card-btn[data-framework="NIST"] { --fw-gradient: linear-gradient(135deg, #a855f7, #7c3aed); --fw-glow: rgba(168, 85, 247, 0.3); }
        .framework-card-btn[data-framework="PCI DSS"] { --fw-gradient: linear-gradient(135deg, #ef4444, #dc2626); --fw-glow: rgba(239, 68, 68, 0.3); }
        .framework-card-btn[data-framework="DPDP"] { --fw-gradient: linear-gradient(135deg, #10b981, #059669); --fw-glow: rgba(16, 185, 129, 0.3); }
        .framework-card-btn[data-framework="SYSTEM"] { --fw-gradient: linear-gradient(135deg, #3b82f6, #2563eb); --fw-glow: rgba(59, 130, 246, 0.3); }
        .framework-card-btn[data-framework="HARDWARE"] { --fw-gradient: linear-gradient(135deg, #f59e0b, #d97706); --fw-glow: rgba(245, 158, 11, 0.3); }
        .framework-card-btn[data-framework="ENDPOINT"] { --fw-gradient: linear-gradient(135deg, #ec4899, #db2777); --fw-glow: rgba(236, 72, 153, 0.3); }
    </style>
</head>

<body>
    <div class="dashboard-container">
        <!-- Critical events banner -->
        <div id="critical-banner" style="
            display: none;
            background: linear-gradient(90deg, #ef4444, #b91c1c);
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 12px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            text-align: center;
            color: white;
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.5);
            animation: pulse 1.5s infinite ease-in-out;">
            ⚠ 0 CRITICAL EVENTS DETECTED
        </div>

        <div class="header-container">
            <h1>Compliance & Configuration Posture</h1>
            <div class="status-panel">
                <div class="status-item">
                    <span id="consumer-dot" class="status-dot idle"></span>
                    <span class="status-label">Consumer:</span>
                    <span id="consumer-val" class="status-val text-idle">LOADING</span>
                </div>
                <div class="status-item">
                    <span id="producer-dot" class="status-dot idle"></span>
                    <span class="status-label">Producer:</span>
                    <span id="producer-val" class="status-val text-idle">LOADING</span>
                </div>
                <div class="status-item clock">
                    <span class="status-label">Local Time:</span>
                    <span class="status-val" id="live-clock">--:--:--</span>
                </div>
                <div class="status-item clock" style="padding-left: 20px;">
                    <span class="status-label">CPU:</span>
                    <span class="status-val" id="sys-cpu" style="color: #38bdf8;">--%</span>
                    <span class="status-label" style="margin-left: 10px;">RAM:</span>
                    <span class="status-val" id="sys-ram" style="color: #a855f7;">--%</span>
                </div>
            </div>
        </div>

        <div class="metrics-container">
            <div class="metric-card card-total">
                <h3>Total Events</h3>
                <p id="metric-total-logs">0</p>
            </div>

            <div class="metric-card card-files">
                <h3>Files</h3>
                <p id="metric-total-files">0</p>
            </div>

            <div class="metric-card card-critical">
                <h3>Critical</h3>
                <p id="metric-critical-count">0</p>
            </div>

            <div class="metric-card card-warning">
                <h3>Warning</h3>
                <p id="metric-warning-count">0</p>
            </div>

            <div class="metric-card card-investigative">
                <h3>Investigative</h3>
                <p id="metric-investigative-count">0</p>
            </div>

            <div class="metric-card card-info">
                <h3>Info</h3>
                <p id="metric-info-count">0</p>
            </div>

            <div class="metric-card card-statistics">
                <h3>Statistics</h3>
                <p id="metric-statistics-count">0</p>
            </div>

            <div class="metric-card card-device">
                <h3>Latest Device</h3>
                <p id="metric-latest-device" style="font-size: 14px; margin-top: 18px; word-break: break-all;">Unknown</p>
            </div>

            <div class="metric-card card-ip">
                <h3>IP Address</h3>
                <p id="metric-latest-ip" style="font-size: 14px; margin-top: 18px; word-break: break-all;">Unknown</p>
            </div>
        </div>

        <div class="main-layout">
            <div class="sidebar">
                <h2>📁 File Wise Logs</h2>
                <div id="sidebar-logs-container">
                    <!-- Dynamic file list accordions go here -->
                </div>
            </div>

            <div class="content">
                <!-- Navigation Tabs -->
                <div class="nav-tabs">
                    <button id="nav-btn-stream" class="nav-tab active" onclick="switchNavTab('stream')">📡 Event Stream</button>
                    <button id="nav-btn-compliance" class="nav-tab" onclick="switchNavTab('compliance')">📊 Compliance Posture</button>
                </div>

                <!-- VIEW 1: Live Event Stream -->
                <div id="view-stream">
                    <h2>📡 Real-time Event Stream (Live)</h2>
                    
                    <!-- Framework Scroll Bar -->
                    <div class="framework-scroll-container" id="framework-scroll-bar">
                        <button data-framework="ALL" class="framework-card-btn active" onclick="filterFramework('ALL')">
                            <h4>All Frameworks</h4>
                            <span id="fw-count-ALL">0 logs</span>
                        </button>
                        <button data-framework="NIST" class="framework-card-btn" onclick="filterFramework('NIST')">
                            <h4>NIST</h4>
                            <span id="fw-count-NIST">0 logs</span>
                        </button>
                        <button data-framework="PCI DSS" class="framework-card-btn" onclick="filterFramework('PCI DSS')">
                            <h4>PCI DSS</h4>
                            <span id="fw-count-PCI-DSS">0 logs</span>
                        </button>
                        <button data-framework="DPDP" class="framework-card-btn" onclick="filterFramework('DPDP')">
                            <h4>DPDP</h4>
                            <span id="fw-count-DPDP">0 logs</span>
                        </button>
                        <button data-framework="SYSTEM" class="framework-card-btn" onclick="filterFramework('SYSTEM')">
                            <h4>SYSTEM</h4>
                            <span id="fw-count-SYSTEM">0 logs</span>
                        </button>
                        <button data-framework="HARDWARE" class="framework-card-btn" onclick="filterFramework('HARDWARE')">
                            <h4>HARDWARE</h4>
                            <span id="fw-count-HARDWARE">0 logs</span>
                        </button>
                        <button data-framework="ENDPOINT" class="framework-card-btn" onclick="filterFramework('ENDPOINT')">
                            <h4>ENDPOINT</h4>
                            <span id="fw-count-ENDPOINT">0 logs</span>
                        </button>
                    </div>

                    <div class="tabs">
                        <button data-severity="ALL" class="active" onclick="filterSeverity('ALL')">All</button>
                        <button data-severity="CRITICAL" onclick="filterSeverity('CRITICAL')">Critical</button>
                        <button data-severity="WARNING" onclick="filterSeverity('WARNING')">Warning</button>
                        <button data-severity="INVESTIGATE" onclick="filterSeverity('INVESTIGATE')">Investigative</button>
                        <button data-severity="INFO" onclick="filterSeverity('INFO')">Info</button>
                        <button data-severity="STATISTICAL" onclick="filterSeverity('STATISTICAL')">Statistics</button>
                    </div>

                    <div class="search-container">
                        <input
                            type="text"
                            id="searchInput"
                            placeholder="Search any field (e.g. Administrator, timestamp, status, file_name, key or value)..."
                            onkeyup="renderEventTable()"
                        >
                    </div>

                    <table>
                        <thead>
                            <tr>
                                <th>File</th>
                                <th>Date & Time</th>
                                <th>Event Summary</th>
                                <th>Severity</th>
                                <th>Compliance %</th>
                            </tr>
                        </thead>
                        <tbody id="event-table-body">
                            <!-- Dynamic event rows go here -->
                        </tbody>
                    </table>
                </div>

                <!-- VIEW 2: Compliance Posture Report -->
                <div id="view-compliance" style="display: none;">
                    <h2>📊 Compliance Posture Report</h2>
                    
                    <!-- Report Summary Widget -->
                    <div id="report-summary-widget" style="margin-bottom: 25px; padding: 20px; background: rgba(17, 24, 39, 0.45); border: 1px solid var(--border-color); border-left: 4px solid var(--color-total); border-radius: 16px; backdrop-filter: blur(10px);">
                        <!-- Dynamic report summary goes here -->
                    </div>

                    <div class="compliance-scores-grid" id="compliance-scores-container" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 25px;">
                        <!-- Dynamic framework score cards go here -->
                    </div>
                    
                    <div style="margin-bottom: 20px; display: flex; align-items: center; gap: 12px; background: rgba(17, 24, 39, 0.4); padding: 12px 20px; border-radius: 30px; border: 1px solid rgba(255, 255, 255, 0.05); width: fit-content;">
                        <label for="frameworkFilterSelect" style="font-weight: 800; font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: #9ca3af;">Filter Framework:</label>
                        <select id="frameworkFilterSelect" onchange="renderComplianceReport()" style="background: rgba(17, 24, 39, 0.85); color: white; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 20px; padding: 6px 16px; font-family: inherit; font-size: 13px; font-weight: 700; outline: none; cursor: pointer; transition: all 0.3s;">
                            <option value="ALL">All Frameworks</option>
                            <option value="NIST">NIST</option>
                            <option value="PCI DSS">PCI DSS</option>
                            <option value="DPDP">DPDP</option>
                            <option value="SYSTEM">SYSTEM</option>
                            <option value="HARDWARE">HARDWARE</option>
                            <option value="ENDPOINT">ENDPOINT</option>
                        </select>
                    </div>

                    <div id="compliance-rules-list" style="display: flex; flex-direction: column; gap: 12px;">
                        <!-- Dynamic compliance checks will be loaded here -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentSeverityFilter = 'ALL';
        let currentFrameworkFilter = 'ALL';
        window.allEvents = [];
        window.latestReportData = {};
        window.maxDisplayedRows = 100;
        
        window.loadMoreLogs = function() {
            window.maxDisplayedRows += 100;
            renderEventTable();
        };

        function filterFramework(fw) {
            currentFrameworkFilter = fw;
            const buttons = document.querySelectorAll('.framework-card-btn');
            buttons.forEach(btn => {
                if (btn.getAttribute('data-framework') === fw) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });
            renderEventTable();
        }

        function showFrameworkLogs(fw) {
            switchNavTab('stream');
            filterFramework(fw);
            const bar = document.getElementById('framework-scroll-bar');
            if (bar) bar.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        function renderReportSummary(report) {
            const container = document.getElementById('report-summary-widget');
            if (!container) return;
            
            if (report && report.summary) {
                const total = report.summary.total_controls_evaluated || 0;
                const passed = report.summary.passed || 0;
                const failed = report.summary.failed || 0;
                const errors = report.summary.errors || 0;
                const hostname = report.hostname || 'N/A';
                const timeStr = report.generated_at ? report.generated_at.replace('T', ' ').substring(0, 19) : 'N/A';
                
                container.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 20px;">
                        <div>
                            <h3 style="margin: 0; font-size: 16px; font-weight: 800; color: #ffffff; text-transform: uppercase; letter-spacing: 0.5px;">📋 Host Compliance Posture Result</h3>
                            <p style="margin: 4px 0 0 0; font-size: 12.5px; color: #9ca3af;">
                                Hostname: <strong style="color: #38bdf8;">${escapeHTML(hostname)}</strong> &nbsp;|&nbsp; 
                                Last Evaluated: <strong style="color: #38bdf8;">${escapeHTML(timeStr)} UTC</strong>
                            </p>
                        </div>
                        <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                            <div style="background: rgba(3, 7, 18, 0.6); padding: 8px 16px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.05); text-align: center; min-width: 90px;">
                                <span style="font-size: 9px; text-transform: uppercase; color: #9ca3af; font-weight: 700; letter-spacing: 0.5px;">Total Rules</span>
                                <div style="font-size: 18px; font-weight: 800; color: #ffffff; font-family: 'JetBrains Mono', monospace;">${total}</div>
                            </div>
                            <div style="background: rgba(16, 185, 129, 0.1); padding: 8px 16px; border-radius: 10px; border: 1px solid rgba(16, 185, 129, 0.2); text-align: center; min-width: 90px;">
                                <span style="font-size: 9px; text-transform: uppercase; color: #10b981; font-weight: 700; letter-spacing: 0.5px;">Passed</span>
                                <div style="font-size: 18px; font-weight: 800; color: #10b981; font-family: 'JetBrains Mono', monospace;">${passed}</div>
                            </div>
                            <div style="background: rgba(239, 68, 68, 0.1); padding: 8px 16px; border-radius: 10px; border: 1px solid rgba(239, 68, 68, 0.2); text-align: center; min-width: 90px;">
                                <span style="font-size: 9px; text-transform: uppercase; color: #ef4444; font-weight: 700; letter-spacing: 0.5px;">Failed</span>
                                <div style="font-size: 18px; font-weight: 800; color: #ef4444; font-family: 'JetBrains Mono', monospace;">${failed}</div>
                            </div>
                            ${errors > 0 ? `
                            <div style="background: rgba(239, 68, 68, 0.2); padding: 8px 16px; border-radius: 10px; border: 1px solid rgba(239, 68, 68, 0.3); text-align: center; min-width: 90px;">
                                <span style="font-size: 9px; text-transform: uppercase; color: #f43f5e; font-weight: 700; letter-spacing: 0.5px;">Errors</span>
                                <div style="font-size: 18px; font-weight: 800; color: #f43f5e; font-family: 'JetBrains Mono', monospace;">${errors}</div>
                            </div>` : ''}
                        </div>
                    </div>
                `;
            } else {
                container.innerHTML = `
                    <div style="text-align: center; color: #9ca3af; font-size: 13px; padding: 10px;">
                        Waiting for compliance report data...
                    </div>
                `;
            }
        }

        const RULE_MAPPINGS = {
            "t10_corr_01": { id: "T10-CORR-01", framework: "SYSTEM", control: "Software to Service Vulnerability Mapping", desc: "Correlates active installed software against running services to identify running unmapped services." },
            "t10_corr_02": { id: "T10-CORR-02", framework: "SYSTEM", control: "Persistence Threat Intel Enrichment", desc: "Correlates autoruns and scheduled tasks against threat intelligence actors/reputations." },
            "01_installed_software": { id: "01_installed_software", framework: "SYSTEM", control: "Installed Software Inventory", desc: "Verifies installed software packages against blacklist policy (e.g. uTorrent, BitTorrent, TeamViewer)." },
            "04_hardware_inventory": { id: "04_hardware_inventory", framework: "SYSTEM", control: "Hardware Asset Inventory", desc: "Audits hardware motherboard, manufacturer, model, and system details." },
            "05_windows_services": { id: "05_windows_services", framework: "SYSTEM", control: "Windows Service Enumeration", desc: "Checks that core baseline windows services are running (e.g. Windows Defender, Firewall)." },
            "06_failed_logins": { id: "AC-7", framework: "NIST", control: "Failed Login Monitoring", desc: "Tracks brute-force logon attempts by auditing Security Event ID 4625." },
            "07_successful_logins": { id: "AU-2", framework: "NIST", control: "Successful Login Auditing", desc: "Audits system access credentials and authentication events (Event ID 4624)." },
            "10_firewall_configuration": { id: "PCI-1.4", framework: "PCI DSS", control: "Firewall Configuration", desc: "Enforces that all 3 local Windows Firewall profiles (Domain, Private, Public) are active." },
            "12_registry_autoruns": { id: "SI-7", framework: "NIST", control: "Registry Autorun Monitoring", desc: "Checks startup registry hives for suspicious file names, paths, or scripts." },
            "13_scheduled_tasks": { id: "AU-12-ST", framework: "DPDP", control: "Scheduled Task Monitoring", desc: "Monitors active scheduled tasks for suspicious binaries or wscript/cscript executions." },
            "16_user_accounts_and_privileges": { id: "AC-6", framework: "NIST", control: "Privileged Account Monitoring", desc: "Scans active user accounts in the administrators group." },
            "17_windows_defender_status": { id: "PCI-5.2", framework: "PCI DSS", control: "Endpoint Protection", desc: "Verifies if Windows Defender real-time protection is enabled." },
            "20_boot_shutdown_events": { id: "AU-5", framework: "NIST", control: "System Boot Monitoring", desc: "Audits log records for system start (Event 6005) and shutdown (Event 6006) events." },
            "21_audit_policy_configuration": { id: "AU-6", framework: "NIST", control: "Audit Policy Monitoring", desc: "Audits default local policy logging settings for login/logout and privilege changes." },
            "22_drivers_inventory": { id: "DRV-01", framework: "SYSTEM", control: "Driver Tree Inventory Mapping", desc: "Enumerates loaded drivers and maps critical hardware drivers." },
            "23_more_windows_settings": { id: "WIN-SET", framework: "SYSTEM", control: "Extended Local Subsystem Regulations", desc: "Verifies extended OS configurations like secure boot, credential guard." },
            "24_usb_direct_connection": { id: "USB-DIR", framework: "HARDWARE", control: "Logical Host Storage Route Identification", desc: "Monitors local host hardware controllers for USB connection states." },
            "25_bios_snapshot": { id: "BIOS-SNAP", framework: "HARDWARE", control: "Firmware Core Configuration Identifiers", desc: "Checks BIOS vendor version and SMBIOS BIOS snapshot parameters." },
            "26_windows_scan_history": { id: "SCAN-HIST", framework: "ENDPOINT", control: "Local Threat History Auditing Logs", desc: "Scans Windows Defender active threat logs history." },
            "27_usb_setting_history": { id: "USB-HIST", framework: "HARDWARE", control: "Historical Peripheral Storage Connectivity Signatures", desc: "Audits historical USB Storage connections from system registry keys." }
        };

        function updateClock() {
            const now = new Date();
            document.getElementById('live-clock').innerText = now.toLocaleTimeString();
        }
        setInterval(updateClock, 1000);
        updateClock();

        function escapeHTML(str) {
            if (typeof str !== 'string') return String(str);
            return str.replace(/[&<>'"]/g, 
                tag => ({
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    "'": '&#39;',
                    '"': '&quot;'
                }[tag] || tag)
            );
        }

        function getEventSummary(record) {
            if (typeof record !== 'object' || record === null) {
                return String(record);
            }
            let targetObj = record;
            if (Array.isArray(record) && record.length > 0) {
                targetObj = record[0];
            } else if (Array.isArray(record)) {
                return "Empty List";
            }
            
            const priorityFields = [
                "task_name", "service_name", "process_name", "ProcessName",
                "name", "Name", "status", "message", "DisplayName",
                "raw_output", "Command", "command"
            ];
            for (let i = 0; i < priorityFields.length; i++) {
                const field = priorityFields[i];
                if (field in targetObj && targetObj[field] !== null && targetObj[field] !== undefined) {
                    let summary = String(targetObj[field]);
                    if (Array.isArray(record) && record.length > 1) {
                        summary += ` (and ${record.length - 1} more)`;
                    }
                    return summary;
                }
            }
            return JSON.stringify(record).substring(0, 120);
        }

        function getCompliancePercentage(severity) {
            const sev = String(severity).toUpperCase();
            if (sev === "CRITICAL") return 25;
            if (sev === "WARNING") return 50;
            if (sev === "INVESTIGATE") return 65;
            if (sev === "STATISTICAL") return 100;
            return 95;
        }

        function containsTerm(obj, term) {
            if (obj === null || obj === undefined) return false;
            if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
                return String(obj).toLowerCase().includes(term);
            }
            if (Array.isArray(obj)) {
                return obj.some(item => containsTerm(item, term));
            }
            if (typeof obj === 'object') {
                return Object.keys(obj).some(key => {
                    if (key.toLowerCase().includes(term)) return true;
                    return containsTerm(obj[key], term);
                });
            }
            return false;
        }

        function getRuleForLog(log) {
            for (let key in RULE_MAPPINGS) {
                if (log.file_name && log.file_name.includes(key)) {
                    let rule = Object.assign({}, RULE_MAPPINGS[key]);
                    rule.datapoint = key;
                    return rule;
                }
            }
            return null;
        }

        function toggleRowDetails(rowElement, logIndex) {
            const nextRow = rowElement.nextElementSibling;
            if (nextRow && nextRow.classList.contains('details-row')) {
                nextRow.remove();
                rowElement.classList.remove('expanded');
                return;
            }
            
            document.querySelectorAll('.details-row').forEach(r => r.remove());
            document.querySelectorAll('tbody tr.expanded').forEach(r => r.classList.remove('expanded'));
            
            const log = window.allEvents[logIndex];
            if (!log) return;
            
            rowElement.classList.add('expanded');
            
            const rule = getRuleForLog(log);
            let ruleHTML = '';
            
            if (rule) {
                let ruleStatus = 'MANUAL REVIEW';
                let ruleEvidence = 'No active scan telemetry for this rule.';
                let statusClass = 'status-warning';
                
                if (window.latestReportData && window.latestReportData.findings) {
                    const findings = window.latestReportData.findings.filter(f => f.datapoint === rule.datapoint);
                    if (findings && findings.length > 0) {
                        const failedFinding = findings.find(f => f.status === 'FAIL');
                        if (failedFinding) {
                            ruleStatus = 'FAIL';
                            ruleEvidence = failedFinding.evidence;
                        } else {
                            ruleStatus = 'PASS';
                            ruleEvidence = findings[0].evidence;
                        }
                        statusClass = ruleStatus === 'PASS' ? 'status-pass' : 'status-fail';
                    }
                }
                
                ruleHTML = `
                    <div class="rule-details-container ${statusClass}" style="margin-bottom: 15px; padding: 15px; border-radius: 8px; border-left: 4px solid var(--border-color); background: rgba(3, 7, 18, 0.4);">
                        <h4 style="margin: 0 0 6px 0; font-size: 14px; font-weight: 800; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.5px;">🛡️ Mapped Compliance Control</h4>
                        <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 10px; flex-wrap: wrap;">
                            <span style="font-size: 12px; font-weight: 700; color: white;">[${rule.id}] ${rule.control}</span>
                            <span style="font-size: 11px; background: rgba(56, 189, 248, 0.1); color: #38bdf8; padding: 2px 8px; border-radius: 10px; font-weight: 700; border: 1px solid rgba(56, 189, 248, 0.2); text-transform: uppercase;">Framework: ${rule.framework}</span>
                             <span class="badge-${ruleStatus.toLowerCase().replace(/\\s+/g, '-')}" style="font-size: 11px; font-weight: 800; padding: 2px 8px; border-radius: 10px;">Rule Status: ${ruleStatus}</span>
                        </div>
                        <p style="margin: 0 0 8px 0; font-size: 12.5px; color: #cbd5e1; line-height: 1.4;">${rule.desc}</p>
                        <div style="background: #030712; padding: 10px; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.03); margin-top: 8px;">
                            <pre style="margin: 0; font-size: 10.5px; color: #e2e8f0; font-family: 'JetBrains Mono', monospace; word-break: break-all; white-space: pre-wrap;"><strong style="color: #38bdf8;">Scan Evidence:</strong> ${escapeHTML(ruleEvidence)}</pre>
                        </div>
                    </div>
                `;
            } else {
                ruleHTML = `
                    <div style="margin-bottom: 15px; padding: 12px; border-radius: 6px; background: rgba(245, 158, 11, 0.05); border: 1px solid rgba(245, 158, 11, 0.15); color: #fde047; font-size: 12.5px;">
                        No mapped compliance control rule found for this event type.
                    </div>
                `;
            }
            
            const detailsRow = document.createElement('tr');
            detailsRow.className = 'details-row';
            detailsRow.innerHTML = `
                <td colspan="5" style="padding: 20px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); box-shadow: inset 0 2px 10px rgba(0,0,0,0.6);">
                    ${ruleHTML}
                    <div style="margin-top: 5px;">
                        <h4 style="margin: 0 0 8px 0; font-size: 12px; font-weight: 800; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px;">📋 Raw Event Payload</h4>
                        <div style="background: #030712; padding: 12px; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.03); max-height: 300px; overflow-y: auto;">
                            <pre style="margin: 0; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #e2e8f0; word-break: break-all; white-space: pre-wrap;">${escapeHTML(JSON.stringify(log, null, 2))}</pre>
                        </div>
                    </div>
                </td>
            `;
            
            rowElement.parentNode.insertBefore(detailsRow, rowElement.nextSibling);
        }

        function renderEventTable() {
            const searchInput = document.getElementById('searchInput');
            const query = searchInput ? searchInput.value.trim().toLowerCase() : '';
            const tbody = document.getElementById('event-table-body');
            if (!tbody || !window.allEvents) return;

            let rowsHTML = '';
            let renderedCount = 0;

            window.allEvents.forEach((log, index) => {
                if (renderedCount >= window.maxDisplayedRows) return;
                
                const severity = log.severity || 'INFO';
                
                if (currentSeverityFilter !== 'ALL' && severity.toUpperCase() !== currentSeverityFilter) {
                    return;
                }

                const rule = getRuleForLog(log);
                const framework = rule ? rule.framework : 'NONE';
                if (currentFrameworkFilter !== 'ALL' && framework !== currentFrameworkFilter) {
                    return;
                }

                if (query && !containsTerm(log, query)) {
                    return;
                }

                renderedCount++;
                const record = log.record || log;
                const summary = getEventSummary(record);
                const compliance = getCompliancePercentage(severity);
                const severityClass = severity.toLowerCase();
                const progressClass = `${severityClass}-fill`;

                rowsHTML += `
                    <tr data-severity="${severity}" onclick="toggleRowDetails(this, ${index})" style="cursor: pointer;">
                        <td style="word-break: break-all;">${escapeHTML(log.file_name || 'unknown')}</td>
                        <td>${escapeHTML(log.timestamp || 'N/A')}</td>
                        <td style="word-break: break-all;">${escapeHTML(summary)}</td>
                        <td class="severity-${severityClass}">${escapeHTML(severity)}</td>
                        <td>
                            <div class="progress-bar">
                                <div class="progress-fill ${progressClass}" style="width:${compliance}%">
                                    ${compliance}%
                                </div>
                            </div>
                        </td>
                    </tr>
                `;
            });
            
            if (renderedCount >= window.maxDisplayedRows) {
                rowsHTML += `<tr><td colspan="5" style="text-align: center; padding: 15px;">
                    <button onclick="window.loadMoreLogs()" style="background: rgba(56, 189, 248, 0.1); border: 1px solid #38bdf8; color: #38bdf8; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; font-family: 'Outfit', sans-serif;">Load Next 100 Logs</button>
                </td></tr>`;
            }

            tbody.innerHTML = rowsHTML;
        }

        function filterSeverity(level) {
            currentSeverityFilter = level.toUpperCase();
            
            const buttons = document.querySelectorAll('.tabs button');
            buttons.forEach(btn => {
                if (btn.getAttribute('data-severity') === level) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });

            renderEventTable();
        }

        function switchNavTab(tabName) {
            const streamBtn = document.getElementById('nav-btn-stream');
            const complianceBtn = document.getElementById('nav-btn-compliance');
            const streamView = document.getElementById('view-stream');
            const complianceView = document.getElementById('view-compliance');
            
            if (tabName === 'stream') {
                streamBtn.className = 'nav-tab active';
                complianceBtn.className = 'nav-tab';
                streamView.style.display = 'block';
                complianceView.style.display = 'none';
            } else {
                streamBtn.className = 'nav-tab';
                complianceBtn.className = 'nav-tab active';
                streamView.style.display = 'none';
                complianceView.style.display = 'block';
                renderComplianceReport();
            }
        }

        function renderFrameworkScores(report) {
            const container = document.getElementById('compliance-scores-container');
            if (!container) return;
            
            let html = '';
            if (report && report.scores) {
                for (let fw in report.scores) {
                    const score = report.scores[fw];
                    let scoreColor = '#10b981';
                    if (score < 50) scoreColor = '#ef4444';
                    else if (score < 80) scoreColor = '#f59e0b';
                    
                    html += `
                        <div class="metric-card" style="border-left: 3px solid ${scoreColor}; cursor: pointer;" onclick="showFrameworkLogs('${escapeHTML(fw)}')">
                            <h3>${escapeHTML(fw)} Score</h3>
                            <p style="color: ${scoreColor}; font-size: 28px;">${score}%</p>
                            <span style="font-size: 10px; color: #9ca3af; margin-top: 5px; display: block; text-transform: uppercase; letter-spacing: 0.5px;">Click to view logs</span>
                        </div>
                    `;
                }
            } else {
                html = `
                    <div style="grid-column: 1 / -1; padding: 15px; background: rgba(255,255,255,0.02); text-align: center; border-radius: 8px; color: #9ca3af; font-size: 13.5px;">
                        No compliance posture scores available. Run report_generator.py to generate score calculations.
                    </div>
                `;
            }
            container.innerHTML = html;
        }

        function toggleRuleAccordion(headerElement) {
            const card = headerElement.parentElement;
            const body = card.querySelector('.rule-body');
            const chevron = card.querySelector('.chevron');
            
            if (body.style.display === 'none') {
                body.style.display = 'block';
                chevron.style.transform = 'rotate(180deg)';
                card.style.borderColor = 'rgba(56, 189, 248, 0.3)';
            } else {
                body.style.display = 'none';
                chevron.style.transform = 'rotate(0deg)';
                card.style.borderColor = 'rgba(255, 255, 255, 0.05)';
            }
        }

        function renderComplianceReport() {
            const container = document.getElementById('compliance-rules-list');
            const select = document.getElementById('frameworkFilterSelect');
            const filter = select ? select.value : 'ALL';
            if (!container) return;
            
            let html = '';
            let rulesList = [];
            
            if (window.latestReportData && window.latestReportData.findings) {
                rulesList = window.latestReportData.findings.map(f => ({
                    id: f.control_id,
                    framework: f.framework,
                    control: f.control_description,
                    desc: "Remediation: " + f.remediation,
                    status: f.status,
                    evidence: f.evidence
                }));
            }
            
            rulesList.sort((a,b) => {
                if (a.framework !== b.framework) return a.framework.localeCompare(b.framework);
                return a.id.localeCompare(b.id);
            });
            
            let renderedCount = 0;
            
            rulesList.forEach(rule => {
                if (filter !== 'ALL' && !rule.framework.includes(filter)) {
                    return;
                }
                
                renderedCount++;
                
                let status = rule.status;
                let evidence = rule.evidence;
                let badgeClass = `badge-${status.toLowerCase().replace(/\\s+/g, '-')}`;
                let statusClass = status === 'PASS' ? 'status-pass' : (status === 'FAIL' ? 'status-fail' : 'status-warning');
                
                html += `
                    <div class="compliance-rule-card ${statusClass}" style="background: rgba(17, 24, 39, 0.4); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 12px; overflow: hidden; margin-bottom: 10px; transition: all 0.3s ease;">
                        <div style="padding: 16px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none;" onclick="toggleRuleAccordion(this)">
                            <div style="display: flex; align-items: center; gap: 12px; text-align: left; flex-wrap: wrap;">
                                <span class="${badgeClass}" style="padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: 800; letter-spacing: 0.5px;">${status}</span>
                                <div>
                                    <h4 style="margin: 0; font-size: 14px; font-weight: 700; color: #ffffff;">${escapeHTML(rule.control)}</h4>
                                    <span style="font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px;">Rule: ${rule.id} | Framework: ${rule.framework}</span>
                                </div>
                            </div>
                            <span class="chevron" style="font-size: 10px; color: #9ca3af; transition: transform 0.2s;">▼</span>
                        </div>
                        <div class="rule-body" style="display: none; padding: 0 16px 16px 16px; border-top: 1px solid rgba(255, 255, 255, 0.05); background: rgba(3, 7, 18, 0.4);">
                            <div style="margin-top: 12px; text-align: left;">
                                <p style="margin: 0 0 8px 0; font-size: 13px; color: #cbd5e1; line-height: 1.4;">${escapeHTML(rule.desc)}</p>
                                <div style="background: #030712; padding: 12px; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.03); margin-top: 8px;">
                                    <pre style="margin: 0; font-size: 11px; color: #cbd5e1; font-family: 'JetBrains Mono', monospace; word-break: break-all; white-space: pre-wrap;"><strong style="color: #38bdf8;">Evidence Gathered:</strong> ${escapeHTML(evidence)}</pre>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            });
            
            if (renderedCount === 0) {
                html = `
                    <div style="padding: 20px; background: rgba(255,255,255,0.02); text-align: center; border-radius: 8px; color: #9ca3af; font-size: 13.5px;">
                        No rules found for framework: ${escapeHTML(filter)}.
                    </div>
                `;
            }
            container.innerHTML = html;
        }

        function updateUI(data) {
            // Update status panel
            const consumerDot = document.getElementById('consumer-dot');
            const consumerVal = document.getElementById('consumer-val');
            consumerDot.className = 'status-dot active pulse-active';
            consumerVal.innerText = 'ACTIVE';
            consumerVal.className = 'status-val text-active';

            const producerDot = document.getElementById('producer-dot');
            const producerVal = document.getElementById('producer-val');
            if (data.producer_active) {
                producerDot.className = 'status-dot active pulse-active';
                producerVal.innerText = 'ACTIVE';
                producerVal.className = 'status-val text-active';
            } else {
                producerDot.className = 'status-dot idle';
                producerVal.innerText = 'IDLE';
                producerVal.className = 'status-val text-idle';
            }

            // Update UI status
            if (document.getElementById('sys-cpu')) {
                document.getElementById('sys-cpu').innerText = (data.cpu_usage || 0) + '%';
                document.getElementById('sys-ram').innerText = (data.ram_usage || 0) + '%';
            }

            // Update metrics
            document.getElementById('metric-total-logs').innerText = data.total_logs;
            document.getElementById('metric-total-files').innerText = data.total_files;
            document.getElementById('metric-critical-count').innerText = data.critical_count;
            document.getElementById('metric-warning-count').innerText = data.warning_count;
            document.getElementById('metric-investigative-count').innerText = data.investigative_count;
            document.getElementById('metric-info-count').innerText = data.info_count;
            document.getElementById('metric-statistics-count').innerText = data.statistics_count;
            document.getElementById('metric-latest-device').innerText = data.latest_device;
            document.getElementById('metric-latest-ip').innerText = data.latest_ip;

            // Critical banner
            const banner = document.getElementById('critical-banner');
            if (data.critical_count > 0) {
                banner.style.display = 'block';
                banner.innerText = `⚠ ${data.critical_count} CRITICAL EVENTS DETECTED`;
            } else {
                banner.style.display = 'none';
            }

            // Update File Wise Logs (Sidebar)
            const openAccordions = new Set();
            document.querySelectorAll('.sidebar details[open]').forEach(details => {
                const fname = details.getAttribute('data-filename');
                if (fname) openAccordions.add(fname);
            });

            const sidebarContainer = document.getElementById('sidebar-logs-container');
            let sidebarHTML = '';
            const sortedFiles = Object.keys(data.file_logs).sort();
            sortedFiles.forEach(fname => {
                const logs = data.file_logs[fname];
                const isOpen = openAccordions.has(fname) ? 'open' : '';
                sidebarHTML += `
                    <details data-filename="${fname}" ${isOpen}>
                        <summary>${escapeHTML(fname)} (${logs.length} logs)</summary>
                `;
                logs.forEach(log => {
                    const pretty = JSON.stringify(log, null, 2);
                    sidebarHTML += `
                        <div class="logcard">
                            <pre>${escapeHTML(pretty)}</pre>
                        </div>
                    `;
                });
                sidebarHTML += `</details>`;
            });
            sidebarContainer.innerHTML = sidebarHTML;

            // Save events and render table
            window.allEvents = data.latest_events || [];

            // Update framework counts dynamically
            const counts = { ALL: window.allEvents.length, NIST: 0, "PCI DSS": 0, DPDP: 0, SYSTEM: 0, HARDWARE: 0, ENDPOINT: 0 };
            window.allEvents.forEach(log => {
                const rule = getRuleForLog(log);
                if (rule && rule.framework in counts) {
                    counts[rule.framework]++;
                }
            });
            
            if (document.getElementById('fw-count-ALL')) {
                document.getElementById('fw-count-ALL').innerText = `${counts.ALL} logs`;
                document.getElementById('fw-count-NIST').innerText = `${counts.NIST} logs`;
                document.getElementById('fw-count-PCI-DSS').innerText = `${counts['PCI DSS']} logs`;
                document.getElementById('fw-count-DPDP').innerText = `${counts.DPDP} logs`;
                document.getElementById('fw-count-SYSTEM').innerText = `${counts.SYSTEM} logs`;
                document.getElementById('fw-count-HARDWARE').innerText = `${counts.HARDWARE} logs`;
                document.getElementById('fw-count-ENDPOINT').innerText = `${counts.ENDPOINT} logs`;
            }

            renderEventTable();

            // Save and render latest compliance report data
            window.latestReportData = data.latest_report || {};
            renderReportSummary(window.latestReportData);
            renderFrameworkScores(window.latestReportData);
            
            // Only update compliance list when view is active to avoid resetting user accordion toggle
            const complianceView = document.getElementById('view-compliance');
            if (complianceView && complianceView.style.display === 'block') {
                renderComplianceReport();
            }
        }

        function reloadDataScript() {
            const oldScript = document.getElementById('data-script');
            if (oldScript) {
                oldScript.remove();
            }
            
            const script = document.createElement('script');
            script.id = 'data-script';
            script.src = 'dashboard_data.js?t=' + Date.now();
            script.onload = function() {
                if (window.dashboardData) {
                    updateUI(window.dashboardData);
                }
            };
            script.onerror = function() {
                console.warn('Waiting for dashboard data updates...');
            };
            document.body.appendChild(script);
        }

        // Poll for updates every 2 seconds
        setInterval(reloadDataScript, 2000);
        window.addEventListener('DOMContentLoaded', reloadDataScript);
    </script>
</body>
"""
    dashboard_file.write_text(html_content, encoding="utf-8")
    print("[+] Wrote static HTML framework")

def write_default_data_file():
    default_data = {
        "total_logs": 0,
        "total_files": 0,
        "critical_count": 0,
        "warning_count": 0,
        "investigative_count": 0,
        "info_count": 0,
        "statistics_count": 0,
        "latest_device": "Unknown",
        "latest_ip": "Unknown",
        "producer_active": False,
        "file_logs": {},
        "latest_events": [],
        "latest_report": {}
    }
    js_content = f"window.dashboardData = {json.dumps(default_data)};"
    data_file.write_text(js_content, encoding="utf-8")
    print("[+] Wrote initial empty dashboard_data.js")

def render_dashboard_data():
    global total_logs_count
    
    total_files = len(file_logs)
    
    latest_device = "Unknown"
    latest_ip = "Unknown"
    
    if latest_events:
        # Kafka partitions can deliver out of order. Find the absolute latest event by timestamp.
        latest_event_by_time = None
        max_ts = 0
        for ev in latest_events:
            ts_str = ev.get("timestamp", "")
            try:
                dt = datetime.strptime(ts_str, "%d-%m-%Y %I:%M:%S %p")
                ts_val = dt.timestamp()
                if ts_val > max_ts:
                    max_ts = ts_val
                    latest_event_by_time = ev
            except Exception:
                pass
        
        if latest_event_by_time:
            fingerprint = latest_event_by_time.get("device_fingerprint")
            if isinstance(fingerprint, dict):
                latest_device = fingerprint.get("device_name", "Unknown")
                latest_ip = fingerprint.get("ip_address", "Unknown")

    critical_count = len([
        x for x in latest_events
        if str(x.get("severity", "")).upper() == "CRITICAL"
    ])

    warning_count = len([
        x for x in latest_events
        if str(x.get("severity", "")).upper() == "WARNING"
    ])

    investigative_count = len([
        x for x in latest_events
        if str(x.get("severity", "")).upper() == "INVESTIGATE"
    ])

    info_count = len([
        x for x in latest_events
        if str(x.get("severity", "")).upper() == "INFO"
    ])

    statistics_count = len([
        x for x in latest_events
        if str(x.get("severity", "")).upper() == "STATISTICAL"
    ])

    # Producer status check
    now_ts = datetime.now().timestamp()
    producer_active = False
    if latest_events:
        latest_received_at = latest_events[0].get("received_at", 0)
        if now_ts - latest_received_at < 15:
            producer_active = True

    # Locate and load the latest compliance report
    reports_dir = Path("reports")
    report_files = sorted(reports_dir.glob("final_report_*.json"))
    latest_report = {}
    if report_files:
        try:
            with open(report_files[-1], "r", encoding="utf-8") as rf:
                latest_report = json.load(rf)
        except Exception as e:
            print(f"[ERROR loading latest report] {e}")

    data = {
        "cpu_usage": psutil.cpu_percent(interval=None),
        "ram_usage": psutil.virtual_memory().percent,
        "total_logs": total_logs_count,
        "total_files": total_files,
        "critical_count": critical_count,
        "warning_count": warning_count,
        "investigative_count": investigative_count,
        "info_count": info_count,
        "statistics_count": statistics_count,
        "latest_device": latest_device,
        "latest_ip": latest_ip,
        "producer_active": producer_active,
        "file_logs": file_logs,
        "latest_events": latest_events,
        "latest_report": latest_report
    }
    
    js_content = f"window.dashboardData = {json.dumps(data, ensure_ascii=False)};"
    data_file.write_text(js_content, encoding="utf-8")

# Initialize consumer
consumer = KafkaConsumer(
    "compliance-data",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    group_id="dashboard-group",
    value_deserializer=lambda x: json.loads(x.decode("utf-8"))
)

# Write baseline files on startup
write_static_html()
write_default_data_file()

print("Listening for Kafka messages... (All history will be kept on disk in reports/dashboard_history.jsonl)")

last_render_time = 0
needs_render = False
last_gc_time = time.time()

# Main consume loop
for message in consumer:
    data = message.value
    
    file_name = data.get("event_id", data.get("file_name", "unknown"))
    payload_data = data.get("record", {})

    # Duplicate detection
    try:
        # Include metadata in the unique hash to prevent ignoring valid events 
        # from different files or timestamps that happen to have identical stdout
        unique_id = {
            "file_name": data.get("file_name", ""),
            "event_id": data.get("event_id", ""),
            "timestamp": data.get("timestamp", ""),
            "record": payload_data
        }
        unique_hash = json.dumps(unique_id, sort_keys=True, default=str)
        if unique_hash in seen_hashes:
            continue
        
        seen_hashes.add(unique_hash)
        seen_hashes_list.append(unique_hash)
    except Exception:
        pass

    # Timestamp handling
    if "timestamp" not in data or not data["timestamp"]:
        data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Record receipt epoch for active producer detection
    data["received_at"] = datetime.now().timestamp()

    # Save to disk append-only log file to preserve all historical events
    try:
        with open(history_file, "a", encoding="utf-8") as hf:
            hf.write(json.dumps(data, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[ERROR writing history] {e}")

    # Track overall logs count
    total_logs_count += 1

    # In-memory structures (Uncapped as per request)
    file_logs[file_name].insert(0, data)

    latest_events.insert(0, data)

    needs_render = True

    # Throttled rendering for CPU/RAM optimization
    now_ts = time.time()
    if needs_render and (now_ts - last_render_time >= 2.0):
        render_dashboard_data()
        last_render_time = time.time()
        needs_render = False
        
        # Occasional garbage collection (every 30s instead of every tick to save CPU)
        if now_ts - last_gc_time >= 30.0:
            gc.collect()
            last_gc_time = now_ts

    print(f"[RECEIVED] {file_name}")
