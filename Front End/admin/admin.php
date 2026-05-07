<?php
// =====================================================
// Scam Shield Admin Analytics Dashboard
// Minimalistic professional reporting page
// =====================================================

// IMPORTANT:
// For production, move these values into environment variables.
$host = getenv('DB_HOST') ?: "gateway01.ap-northeast-1.prod.aws.tidbcloud.com";
$port = intval(getenv('DB_PORT') ?: 4000);
$user = getenv('DB_USER') ?: "2tTaktaCaayA81a.root";
$password = getenv('DB_PASSWORD') ?: "Wy8eIW3or3dQ6KeR";
$database = getenv('DB_NAME') ?: "test";

$conn = mysqli_init();

mysqli_real_connect(
    $conn,
    $host,
    $user,
    $password,
    $database,
    $port,
    NULL,
    MYSQLI_CLIENT_SSL
);

if (mysqli_connect_errno()) {
    http_response_code(500);
    die("Connection failed: " . htmlspecialchars(mysqli_connect_error()));
}

mysqli_set_charset($conn, "utf8mb4");

function fetchAll($conn, $sql)
{
    $result = mysqli_query($conn, $sql);

    if (!$result) {
        error_log("SQL error: " . mysqli_error($conn));
        return [];
    }

    $rows = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $rows[] = $row;
    }

    return $rows;
}

function e($value)
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function firstValue($rows, $key, $fallback = 0)
{
    return $rows[0][$key] ?? $fallback;
}

function riskPercent($score)
{
    $raw = floatval($score);
    $percent = $raw <= 1 ? $raw * 100 : $raw;
    return min(100, max(0, $percent));
}

function riskClass($level)
{
    $level = strtoupper(trim((string) $level));
    return in_array($level, ['HIGH', 'MEDIUM', 'LOW']) ? $level : 'UNKNOWN';
}

// =====================================================
// KPI Queries
// =====================================================

$totalLogs = firstValue(fetchAll($conn, "
    SELECT COUNT(*) AS total
    FROM sms_scam_logs
"), "total", 0);

$highRisk = firstValue(fetchAll($conn, "
    SELECT COUNT(*) AS total
    FROM sms_scam_logs
    WHERE UPPER(risk_level) = 'HIGH'
       OR risk_score >= 70
       OR (risk_score >= 0.7 AND risk_score <= 1)
"), "total", 0);

$avgRisk = firstValue(fetchAll($conn, "
    SELECT ROUND(AVG(
        CASE
            WHEN risk_score <= 1 THEN risk_score * 100
            ELSE risk_score
        END
    ), 1) AS avg_risk
    FROM sms_scam_logs
"), "avg_risk", 0);

$uniquePhones = firstValue(fetchAll($conn, "
    SELECT COUNT(DISTINCT phone_number) AS total
    FROM sms_scam_logs
"), "total", 0);

$latestScan = firstValue(fetchAll($conn, "
    SELECT MAX(created_at) AS latest_scan
    FROM sms_scam_logs
"), "latest_scan", "No data");

$highRiskRate = $totalLogs > 0 ? round(($highRisk / $totalLogs) * 100, 1) : 0;

// =====================================================
// Analytics Queries
// =====================================================

$riskLevels = fetchAll($conn, "

    SELECT

        UPPER(COALESCE(NULLIF(risk_level, ''), 'UNKNOWN')) AS risk_level,

        COUNT(*) AS total

    FROM sms_scam_logs

    GROUP BY risk_level

    ORDER BY

        CASE risk_level

            WHEN 'LOW' THEN 1

            WHEN 'MEDIUM' THEN 2

            WHEN 'HIGH' THEN 3

            ELSE 4

        END

");

$verdicts = fetchAll($conn, "
    SELECT COALESCE(NULLIF(verdict, ''), 'Unknown') AS verdict, COUNT(*) AS total
    FROM sms_scam_logs
    GROUP BY COALESCE(NULLIF(verdict, ''), 'Unknown')
    ORDER BY total DESC
");

$dailyTrend = fetchAll($conn, "
    SELECT DATE(created_at) AS date_label, COUNT(*) AS total
    FROM sms_scam_logs
    GROUP BY DATE(created_at)
    ORDER BY DATE(created_at) DESC
    LIMIT 30
");
$dailyTrend = array_reverse($dailyTrend);

$hourlyTrend = fetchAll($conn, "
    SELECT HOUR(created_at) AS hour_label, COUNT(*) AS total
    FROM sms_scam_logs
    GROUP BY HOUR(created_at)
    ORDER BY hour_label
");

$messageTypes = fetchAll($conn, "
    SELECT
        CASE
            WHEN LOWER(sms_content) LIKE '%bank%'
              OR LOWER(sms_content) LIKE '%maybank%'
              OR LOWER(sms_content) LIKE '%cimb%'
              OR LOWER(sms_content) LIKE '%rhb%'
              OR LOWER(sms_content) LIKE '%account%'
            THEN 'Banking Scam'

            WHEN LOWER(sms_content) LIKE '%otp%'
              OR LOWER(sms_content) LIKE '%code%'
              OR LOWER(sms_content) LIKE '%verification%'
              OR LOWER(sms_content) LIKE '%tac%'
            THEN 'OTP / Verification'

            WHEN LOWER(sms_content) LIKE '%parcel%'
              OR LOWER(sms_content) LIKE '%delivery%'
              OR LOWER(sms_content) LIKE '%courier%'
              OR LOWER(sms_content) LIKE '%tracking%'
            THEN 'Parcel / Delivery'

            WHEN LOWER(sms_content) LIKE '%prize%'
              OR LOWER(sms_content) LIKE '%winner%'
              OR LOWER(sms_content) LIKE '%reward%'
              OR LOWER(sms_content) LIKE '%claim%'
            THEN 'Prize / Reward'

            WHEN LOWER(sms_content) LIKE '%loan%'
              OR LOWER(sms_content) LIKE '%cash%'
              OR LOWER(sms_content) LIKE '%credit%'
              OR LOWER(sms_content) LIKE '%duit%'
            THEN 'Loan / Money'

            WHEN LOWER(sms_content) LIKE '%http%'
              OR LOWER(sms_content) LIKE '%www%'
              OR LOWER(sms_content) LIKE '%.com%'
              OR LOWER(sms_content) LIKE '%.ly%'
            THEN 'Suspicious Link'

            ELSE 'Other'
        END AS message_type,
        COUNT(*) AS total
    FROM sms_scam_logs
    GROUP BY message_type
    ORDER BY total DESC
");

$keywordStats = fetchAll($conn, "
    SELECT 'OTP' AS keyword, COUNT(*) AS total FROM sms_scam_logs WHERE LOWER(sms_content) LIKE '%otp%'
    UNION ALL
    SELECT 'Bank', COUNT(*) FROM sms_scam_logs WHERE LOWER(sms_content) LIKE '%bank%'
    UNION ALL
    SELECT 'Link', COUNT(*) FROM sms_scam_logs WHERE LOWER(sms_content) LIKE '%http%' OR LOWER(sms_content) LIKE '%www%'
    UNION ALL
    SELECT 'Claim', COUNT(*) FROM sms_scam_logs WHERE LOWER(sms_content) LIKE '%claim%'
    UNION ALL
    SELECT 'Prize', COUNT(*) FROM sms_scam_logs WHERE LOWER(sms_content) LIKE '%prize%'
    UNION ALL
    SELECT 'Loan', COUNT(*) FROM sms_scam_logs WHERE LOWER(sms_content) LIKE '%loan%'
    UNION ALL
    SELECT 'Parcel', COUNT(*) FROM sms_scam_logs WHERE LOWER(sms_content) LIKE '%parcel%'
");

$topPhones = fetchAll($conn, "
    SELECT
        phone_number,
        COUNT(*) AS total_sms,
        ROUND(AVG(
            CASE
                WHEN risk_score <= 1 THEN risk_score * 100
                ELSE risk_score
            END
        ), 1) AS avg_risk,
        MAX(created_at) AS last_seen
    FROM sms_scam_logs
    GROUP BY phone_number
    ORDER BY total_sms DESC, avg_risk DESC
    LIMIT 10
");

$recentLogs = fetchAll($conn, "
    SELECT
        id,
        phone_number,
        sms_content,
        risk_score,
        UPPER(COALESCE(NULLIF(risk_level, ''), 'UNKNOWN')) AS risk_level,
        COALESCE(NULLIF(verdict, ''), 'Unknown') AS verdict,
        created_at
    FROM sms_scam_logs
    ORDER BY created_at DESC
    LIMIT 150
");
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Scam Shield | Admin Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        :root {
            --bg: #f6f7fb;
            --panel: #ffffff;
            --panel-soft: #f9fafb;
            --text: #111827;
            --muted: #6b7280;
            --line: #e5e7eb;
            --line-dark: #d1d5db;
            --brand: #111827;
            --blue: #2563eb;
            --green: #16a34a;
            --amber: #d97706;
            --red: #dc2626;
            --purple: #7c3aed;
            --shadow: 0 18px 45px rgba(15, 23, 42, 0.06);
            --radius: 18px;
        }

        * {
            box-sizing: border-box;
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            margin: 0;
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background:
                radial-gradient(circle at top left, rgba(37, 99, 235, 0.08), transparent 32rem),
                var(--bg);
            color: var(--text);
        }

        a {
            color: inherit;
        }

        .app {
            min-height: 100vh;
            display: grid;
            grid-template-columns: 260px minmax(0, 1fr);
        }

        .sidebar {
            position: sticky;
            top: 0;
            height: 100vh;
            background: rgba(255, 255, 255, 0.84);
            backdrop-filter: blur(16px);
            border-right: 1px solid var(--line);
            padding: 24px 20px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 28px;
        }

        .brand-mark {
            width: 40px;
            height: 40px;
            border-radius: 14px;
            background: #111827;
            color: #fff;
            display: grid;
            place-items: center;
            font-weight: 800;
            box-shadow: var(--shadow);
        }

        .brand-title {
            font-weight: 800;
            letter-spacing: -0.03em;
        }

        .brand-subtitle {
            color: var(--muted);
            font-size: 12px;
            margin-top: 2px;
        }

        .nav-section {
            margin-top: 18px;
        }

        .nav-label {
            color: var(--muted);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin: 0 0 10px 10px;
            font-weight: 700;
        }

        .nav {
            display: grid;
            gap: 6px;
        }

        .nav a {
            text-decoration: none;
            color: #374151;
            padding: 10px 12px;
            border-radius: 12px;
            font-size: 14px;
            transition: 0.2s ease;
        }

        .nav a:hover,
        .nav a.active {
            background: #111827;
            color: #fff;
        }

        .sidebar-footer {
            position: absolute;
            left: 20px;
            right: 20px;
            bottom: 22px;
            padding: 14px;
            border: 1px solid var(--line);
            border-radius: 16px;
            background: var(--panel-soft);
        }

        .sidebar-footer .small {
            font-size: 12px;
            color: var(--muted);
        }

        .content {
            padding: 28px;
            max-width: 1500px;
            width: 100%;
            margin: 0 auto;
        }

        .topbar {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 24px;
        }

        .eyebrow {
            color: var(--blue);
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.09em;
            margin-bottom: 8px;
        }

        h1 {
            margin: 0;
            font-size: clamp(28px, 4vw, 42px);
            line-height: 1.05;
            letter-spacing: -0.055em;
        }

        .subtitle {
            color: var(--muted);
            margin-top: 12px;
            font-size: 15px;
            max-width: 700px;
        }

        .actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            justify-content: flex-end;
        }

        .btn {
            border: 1px solid var(--line-dark);
            background: var(--panel);
            color: var(--text);
            border-radius: 999px;
            padding: 10px 14px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 10px 20px rgba(15, 23, 42, 0.04);
        }

        .btn.primary {
            background: #111827;
            color: #fff;
            border-color: #111827;
        }

        .report-strip {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 14px 16px;
            background: #111827;
            color: #fff;
            border-radius: var(--radius);
            margin-bottom: 18px;
            box-shadow: var(--shadow);
        }

        .report-strip .muted-white {
            color: rgba(255, 255, 255, 0.7);
            font-size: 13px;
        }

        .connection-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            white-space: nowrap;
            border: 1px solid rgba(255, 255, 255, 0.14);
            background: rgba(255, 255, 255, 0.08);
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 800;
        }

        .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #22c55e;
        }

        .kpis {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 14px;
            margin-bottom: 18px;
        }

        .kpi {
            background: rgba(255, 255, 255, 0.86);
            border: 1px solid var(--line);
            border-radius: var(--radius);
            padding: 18px;
            box-shadow: var(--shadow);
        }

        .kpi-label {
            color: var(--muted);
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }

        .kpi-value {
            margin-top: 10px;
            font-size: 30px;
            font-weight: 800;
            letter-spacing: -0.04em;
        }

        .kpi-note {
            margin-top: 8px;
            color: var(--muted);
            font-size: 12px;
        }

        .danger {
            color: var(--red);
        }

        .warning {
            color: var(--amber);
        }

        .success {
            color: var(--green);
        }

        .info {
            color: var(--blue);
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 14px;
            margin-bottom: 18px;
        }

        .panel {
            background: rgba(255, 255, 255, 0.88);
            border: 1px solid var(--line);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            padding: 18px;
            min-width: 0;
        }

        .span-3 {
            grid-column: span 3;
        }

        .span-4 {
            grid-column: span 4;
        }

        .span-6 {
            grid-column: span 6;
        }

        .span-8 {
            grid-column: span 8;
        }

        .span-12 {
            grid-column: span 12;
        }

        .panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 14px;
        }

        .panel-title {
            margin: 0;
            font-size: 16px;
            letter-spacing: -0.02em;
        }

        .panel-caption {
            color: var(--muted);
            font-size: 12px;
        }

        .chart-wrap {
            position: relative;
            height: 300px;
        }

        .chart-wrap.small {
            height: 250px;
        }

        .toolbar {
            display: flex;
            gap: 10px;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 14px;
            flex-wrap: wrap;
        }

        .search {
            position: relative;
            flex: 1;
            min-width: 260px;
        }

        .search input,
        .select {
            width: 100%;
            border: 1px solid var(--line-dark);
            background: #fff;
            color: var(--text);
            border-radius: 999px;
            padding: 11px 14px;
            outline: none;
            font-size: 13px;
        }

        .search input:focus,
        .select:focus {
            border-color: #93c5fd;
            box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.12);
        }

        .select-wrap {
            width: 170px;
        }

        .table-wrap {
            overflow: auto;
            border: 1px solid var(--line);
            border-radius: 16px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 900px;
            background: #fff;
        }

        th {
            position: sticky;
            top: 0;
            z-index: 2;
            text-align: left;
            background: #f9fafb;
            color: #6b7280;
            border-bottom: 1px solid var(--line);
            padding: 12px 14px;
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            white-space: nowrap;
        }

        td {
            border-bottom: 1px solid #f3f4f6;
            padding: 12px 14px;
            font-size: 13px;
            vertical-align: top;
        }

        tbody tr:hover td {
            background: #fafafa;
        }

        tbody tr:last-child td {
            border-bottom: none;
        }

        .mono {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }

        .sms {
            max-width: 520px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            color: #374151;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 5px 10px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 800;
            border: 1px solid transparent;
            min-width: 72px;
        }

        .badge.HIGH {
            background: #fef2f2;
            color: #991b1b;
            border-color: #fecaca;
        }

        .badge.MEDIUM {
            background: #fffbeb;
            color: #92400e;
            border-color: #fde68a;
        }

        .badge.LOW {
            background: #f0fdf4;
            color: #166534;
            border-color: #bbf7d0;
        }

        .badge.UNKNOWN {
            background: #f3f4f6;
            color: #374151;
            border-color: #e5e7eb;
        }

        .riskbar {
            width: 120px;
            height: 9px;
            border-radius: 999px;
            background: #e5e7eb;
            overflow: hidden;
            margin-top: 5px;
        }

        .riskfill {
            height: 100%;
            border-radius: 999px;
            background: linear-gradient(90deg, #16a34a, #d97706, #dc2626);
        }

        .risk-number {
            font-weight: 800;
            font-size: 12px;
        }

        .empty {
            color: var(--muted);
            padding: 16px;
            text-align: center;
        }

        .print-only {
            display: none;
        }

        @media (max-width: 1200px) {
            .kpis {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .span-3,
            .span-4,
            .span-6,
            .span-8 {
                grid-column: span 12;
            }
        }

        @media (max-width: 860px) {
            .app {
                grid-template-columns: 1fr;
            }

            .sidebar {
                display: none;
            }

            .content {
                padding: 18px;
            }

            .topbar,
            .report-strip {
                flex-direction: column;
                align-items: stretch;
            }

            .actions {
                justify-content: flex-start;
            }

            .kpis {
                grid-template-columns: 1fr;
            }
        }

        @media print {
            body {
                background: #fff;
            }

            .sidebar,
            .actions,
            .toolbar,
            .btn {
                display: none !important;
            }

            .app {
                display: block;
            }

            .content {
                padding: 0;
                max-width: none;
            }

            .panel,
            .kpi,
            .report-strip {
                box-shadow: none;
                break-inside: avoid;
            }

            .print-only {
                display: block;
            }
        }
    </style>
</head>

<body>
    <div class="app">
        <aside class="sidebar">
            <div class="brand">
                <div class="brand-mark">S</div>
                <div>
                    <div class="brand-title">Scam Shield</div>
                    <div class="brand-subtitle">Threat Reporting Console</div>
                </div>
            </div>

            <div class="nav-section">
                <div class="nav-label">Report</div>
                <nav class="nav">
                    <a class="active" href="#overview">Overview</a>
                    <a href="#risk">Risk Analytics</a>
                    <a href="#patterns">Message Patterns</a>
                    <a href="#phones">Phone Numbers</a>
                    <a href="#logs">SMS Logs</a>
                </nav>
            </div>

            <div class="sidebar-footer">
                <div class="small">Database</div>
                <strong><?= e($database) ?></strong>
                <div class="small" style="margin-top:8px;">Connection encrypted with SSL</div>
            </div>
        </aside>

        <main class="content">
            <section id="overview" class="topbar">
                <div>
                    <div class="eyebrow">Security Analytics</div>
                    <h1>SMS Scam Intelligence Report</h1>
                    <div class="subtitle">
                        Clean reporting view for scanned SMS activity, high-risk detections, suspicious keywords,
                        sender behavior, and recent threat logs.
                    </div>
                </div>

                <div class="actions">
                    <button class="btn" onclick="window.location.reload()">Refresh</button>
                    <button class="btn primary" onclick="window.print()">Export PDF</button>
                </div>
            </section>

            <section class="report-strip">
                <div>
                    <strong>Reporting snapshot</strong>
                    <div class="muted-white">Latest scan: <?= e($latestScan) ?></div>
                </div>
                <div class="connection-pill"><span class="dot"></span> SSL Connected</div>
            </section>

            <section class="kpis">
                <div class="kpi">
                    <div class="kpi-label">Total SMS Scanned</div>
                    <div class="kpi-value"><?= e(number_format((float) $totalLogs)) ?></div>
                    <div class="kpi-note">All records processed</div>
                </div>

                <div class="kpi">
                    <div class="kpi-label">High Risk SMS</div>
                    <div class="kpi-value danger"><?= e(number_format((float) $highRisk)) ?></div>
                    <div class="kpi-note">Flagged as likely scam</div>
                </div>

                <div class="kpi">
                    <div class="kpi-label">High Risk Rate</div>
                    <div class="kpi-value danger"><?= e($highRiskRate) ?>%</div>
                    <div class="kpi-note">High-risk share of total</div>
                </div>

                <div class="kpi">
                    <div class="kpi-label">Average Risk Score</div>
                    <div class="kpi-value warning"><?= e($avgRisk) ?>%</div>
                    <div class="kpi-note">Normalized to percentage</div>
                </div>

                <div class="kpi">
                    <div class="kpi-label">Unique Senders</div>
                    <div class="kpi-value success"><?= e(number_format((float) $uniquePhones)) ?></div>
                    <div class="kpi-note">Distinct phone numbers</div>
                </div>
            </section>

            <section id="risk" class="grid">
                <div class="panel span-4">
                    <div class="panel-header">
                        <div>
                            <h2 class="panel-title">Risk Level Distribution</h2>
                            <div class="panel-caption">Breakdown by LOW, MEDIUM, HIGH</div>
                        </div>
                    </div>
                    <div class="chart-wrap small"><canvas id="riskChart"></canvas></div>
                </div>

                <div class="panel span-4">
                    <div class="panel-header">
                        <div>
                            <h2 class="panel-title">Verdict Breakdown</h2>
                            <div class="panel-caption">Classifier decision summary</div>
                        </div>
                    </div>
                    <div class="chart-wrap small"><canvas id="verdictChart"></canvas></div>
                </div>

                <div class="panel span-4">
                    <div class="panel-header">
                        <div>
                            <h2 class="panel-title">Suspicious Keywords</h2>
                            <div class="panel-caption">Common trigger words found</div>
                        </div>
                    </div>
                    <div class="chart-wrap small"><canvas id="keywordChart"></canvas></div>
                </div>

                <div class="panel span-8">
                    <div class="panel-header">
                        <div>
                            <h2 class="panel-title">Daily SMS Trend</h2>
                            <div class="panel-caption">Last 30 recorded days</div>
                        </div>
                    </div>
                    <div class="chart-wrap"><canvas id="dailyChart"></canvas></div>
                </div>

                <div class="panel span-4">
                    <div class="panel-header">
                        <div>
                            <h2 class="panel-title">Hourly Activity</h2>
                            <div class="panel-caption">Volume by hour of day</div>
                        </div>
                    </div>
                    <div class="chart-wrap"><canvas id="hourlyChart"></canvas></div>
                </div>
            </section>

            <section id="patterns" class="grid">
                <div class="panel span-12">
                    <div class="panel-header">
                        <div>
                            <h2 class="panel-title">Message Type Detection</h2>
                            <div class="panel-caption">Rule-based categorization from SMS content</div>
                        </div>
                    </div>
                    <div class="chart-wrap"><canvas id="messageTypeChart"></canvas></div>
                </div>
            </section>

            <section id="phones" class="panel" style="margin-bottom:18px;">
                <div class="panel-header">
                    <div>
                        <h2 class="panel-title">Top Phone Numbers</h2>
                        <div class="panel-caption">Senders with the highest SMS volume</div>
                    </div>
                </div>

                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Phone Number</th>
                                <th>Total SMS</th>
                                <th>Average Risk</th>
                                <th>Last Seen</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($topPhones)) { ?>
                                <tr>
                                    <td colspan="4" class="empty">No sender data available.</td>
                                </tr>
                            <?php } ?>

                            <?php foreach ($topPhones as $phone) { ?>
                                <tr>
                                    <td class="mono"><?= e($phone["phone_number"]) ?></td>
                                    <td><?= e(number_format((float) $phone["total_sms"])) ?></td>
                                    <td>
                                        <span class="risk-number"><?= e($phone["avg_risk"]) ?>%</span>
                                        <div class="riskbar">
                                            <div class="riskfill"
                                                style="width: <?= e(min(100, max(0, floatval($phone["avg_risk"])))) ?>%;">
                                            </div>
                                        </div>
                                    </td>
                                    <td><?= e($phone["last_seen"]) ?></td>
                                </tr>
                            <?php } ?>
                        </tbody>
                    </table>
                </div>
            </section>

            <section id="logs" class="panel">
                <div class="panel-header">
                    <div>
                        <h2 class="panel-title">Recent SMS Logs</h2>
                        <div class="panel-caption">Latest 150 records from sms_scam_logs</div>
                    </div>
                </div>

                <div class="toolbar">
                    <div class="search">
                        <input type="text" id="searchInput"
                            placeholder="Search phone, SMS content, verdict, risk level..." onkeyup="filterTable()">
                    </div>
                    <div class="select-wrap">
                        <select class="select" id="riskFilter" onchange="filterTable()">
                            <option value="">All Risk Levels</option>
                            <option value="HIGH">High</option>
                            <option value="MEDIUM">Medium</option>
                            <option value="LOW">Low</option>
                            <option value="UNKNOWN">Unknown</option>
                        </select>
                    </div>
                </div>

                <div class="table-wrap">
                    <table id="logsTable">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Phone</th>
                                <th>SMS Content</th>
                                <th>Risk</th>
                                <th>Level</th>
                                <th>Verdict</th>
                                <th>Created At</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($recentLogs)) { ?>
                                <tr>
                                    <td colspan="7" class="empty">No SMS logs available.</td>
                                </tr>
                            <?php } ?>

                            <?php foreach ($recentLogs as $log) {
                                $percent = riskPercent($log["risk_score"]);
                                $level = riskClass($log["risk_level"]);
                                ?>
                                <tr data-risk-level="<?= e($level) ?>">
                                    <td class="mono"><?= e($log["id"]) ?></td>
                                    <td class="mono"><?= e($log["phone_number"]) ?></td>
                                    <td class="sms" title="<?= e($log["sms_content"]) ?>"><?= e($log["sms_content"]) ?></td>
                                    <td>
                                        <span class="risk-number"><?= e(round($percent, 1)) ?>%</span>
                                        <div class="riskbar">
                                            <div class="riskfill" style="width: <?= e($percent) ?>%;"></div>
                                        </div>
                                    </td>
                                    <td><span class="badge <?= e($level) ?>"><?= e($level) ?></span></td>
                                    <td><?= e($log["verdict"]) ?></td>
                                    <td><?= e($log["created_at"]) ?></td>
                                </tr>
                            <?php } ?>
                        </tbody>
                    </table>
                </div>
            </section>
        </main>
    </div>

    <script>
        const chartFont = "Inter, Segoe UI, Arial, sans-serif";

        Chart.defaults.color = "#6b7280";
        Chart.defaults.borderColor = "#e5e7eb";
        Chart.defaults.font.family = chartFont;
        Chart.defaults.plugins.tooltip.backgroundColor = "#111827";
        Chart.defaults.plugins.tooltip.padding = 12;
        Chart.defaults.plugins.tooltip.cornerRadius = 10;

        const riskLabels = <?= json_encode(array_column($riskLevels, "risk_level")) ?>;
        const riskData = <?= json_encode(array_map('intval', array_column($riskLevels, "total"))) ?>;

        const verdictLabels = <?= json_encode(array_column($verdicts, "verdict")) ?>;
        const verdictData = <?= json_encode(array_map('intval', array_column($verdicts, "total"))) ?>;

        const dailyLabels = <?= json_encode(array_column($dailyTrend, "date_label")) ?>;
        const dailyData = <?= json_encode(array_map('intval', array_column($dailyTrend, "total"))) ?>;

        const hourlyLabels = <?= json_encode(array_column($hourlyTrend, "hour_label")) ?>;
        const hourlyData = <?= json_encode(array_map('intval', array_column($hourlyTrend, "total"))) ?>;

        const messageTypeLabels = <?= json_encode(array_column($messageTypes, "message_type")) ?>;
        const messageTypeData = <?= json_encode(array_map('intval', array_column($messageTypes, "total"))) ?>;

        const keywordLabels = <?= json_encode(array_column($keywordStats, "keyword")) ?>;
        const keywordData = <?= json_encode(array_map('intval', array_column($keywordStats, "total"))) ?>;

        const palette = {
            black: "#111827",
            blue: "#2563eb",
            green: "#16a34a",
            amber: "#d97706",
            red: "#dc2626",
            purple: "#7c3aed",
            gray: "#9ca3af"
        };

        function baseOptions(extra = {}) {
            return {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            usePointStyle: true,
                            boxWidth: 8,
                            padding: 18
                        }
                    }
                },
                ...extra
            };
        }

        new Chart(document.getElementById("riskChart"), {
            type: "doughnut",
            data: {
                labels: riskLabels,
                datasets: [{
                    data: riskData,
                    backgroundColor: [palette.green, palette.amber, palette.red, palette.gray],
                    borderWidth: 0,
                    hoverOffset: 8
                }]
            },
            options: baseOptions({ cutout: "68%" })
        });

        new Chart(document.getElementById("verdictChart"), {
            type: "doughnut",
            data: {
                labels: verdictLabels,
                datasets: [{
                    data: verdictData,
                    backgroundColor: [palette.red, palette.green, palette.amber, palette.blue, palette.gray],
                    borderWidth: 0,
                    hoverOffset: 8
                }]
            },
            options: baseOptions({ cutout: "68%" })
        });

        new Chart(document.getElementById("keywordChart"), {
            type: "bar",
            data: {
                labels: keywordLabels,
                datasets: [{
                    label: "Keyword hits",
                    data: keywordData,
                    backgroundColor: palette.black,
                    borderRadius: 10,
                    maxBarThickness: 42
                }]
            },
            options: baseOptions({
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } },
                    y: { beginAtZero: true, ticks: { precision: 0 } }
                }
            })
        });

        new Chart(document.getElementById("dailyChart"), {
            type: "line",
            data: {
                labels: dailyLabels,
                datasets: [{
                    label: "SMS scanned",
                    data: dailyData,
                    borderColor: palette.blue,
                    backgroundColor: "rgba(37, 99, 235, 0.10)",
                    pointBackgroundColor: palette.blue,
                    pointRadius: 3,
                    pointHoverRadius: 5,
                    fill: true,
                    tension: 0.35
                }]
            },
            options: baseOptions({
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } },
                    y: { beginAtZero: true, ticks: { precision: 0 } }
                }
            })
        });

        new Chart(document.getElementById("hourlyChart"), {
            type: "bar",
            data: {
                labels: hourlyLabels.map(h => String(h).padStart(2, "0") + ":00"),
                datasets: [{
                    label: "SMS count",
                    data: hourlyData,
                    backgroundColor: palette.purple,
                    borderRadius: 10,
                    maxBarThickness: 34
                }]
            },
            options: baseOptions({
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } },
                    y: { beginAtZero: true, ticks: { precision: 0 } }
                }
            })
        });

        new Chart(document.getElementById("messageTypeChart"), {
            type: "bar",
            data: {
                labels: messageTypeLabels,
                datasets: [{
                    label: "Messages",
                    data: messageTypeData,
                    backgroundColor: palette.black,
                    borderRadius: 10,
                    maxBarThickness: 46
                }]
            },
            options: baseOptions({
                indexAxis: "y",
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, ticks: { precision: 0 } },
                    y: { grid: { display: false } }
                }
            })
        });

        function filterTable() {
            const search = document.getElementById("searchInput").value.toLowerCase().trim();
            const selectedRisk = document.getElementById("riskFilter").value;
            const rows = document.querySelectorAll("#logsTable tbody tr");

            rows.forEach(row => {
                const text = row.innerText.toLowerCase();
                const riskLevel = row.getAttribute("data-risk-level") || "";
                const matchesSearch = !search || text.includes(search);
                const matchesRisk = !selectedRisk || riskLevel === selectedRisk;
                row.style.display = matchesSearch && matchesRisk ? "" : "none";
            });
        }
    </script>
</body>

</html>