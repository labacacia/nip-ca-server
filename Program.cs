// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using NPS.Daemon.Observability;
using NPS.Daemon.Observability.Logging;
using NPS.Daemon.Observability.Shutdown;
using NPS.NIP.Ca;
using NPS.NIP.Crypto;
using NPS.NIP.Extensions;
using NPS.NipCaServer.Observability;

var builder = WebApplication.CreateBuilder(args);

// ── Port configuration ─────────────────────────────────────────────────────
// Public CA port — reachable by agents and nodes.
var publicPort = builder.Configuration.GetValue("NipCa:Port", 17435);

// Management address — serves /metrics, and accepts /healthz + /readyz.
// Defaults to loopback so Prometheus scrapers must be co-located or
// tunnelled; set NIPCA__MGMT_ADDR to expose on a wider interface.
var mgmtAddrRaw  = builder.Configuration["NipCa:MgmtAddr"] ?? "127.0.0.1:17436";
var mgmtColonIdx = mgmtAddrRaw.LastIndexOf(':');
var mgmtHost     = mgmtColonIdx > 0 ? mgmtAddrRaw[..mgmtColonIdx] : "127.0.0.1";
var mgmtPort     = mgmtColonIdx > 0 && int.TryParse(mgmtAddrRaw[(mgmtColonIdx + 1)..], out var p) ? p : 17436;
var mgmtIp       = mgmtHost is "localhost" or "127.0.0.1"
    ? IPAddress.Loopback
    : IPAddress.Parse(mgmtHost);

builder.WebHost.ConfigureKestrel(opts =>
{
    opts.ListenAnyIP(publicPort);       // public CA endpoint
    opts.Listen(mgmtIp, mgmtPort);     // management-only endpoint
});


// ── Logging ────────────────────────────────────────────────────────────────
// Single-line JSON to stdout. Min level controlled by NPS_LOG_LEVEL.
builder.Logging.AddNpsJsonConsole();

// ── Configuration ──────────────────────────────────────────────────────────
// All secrets MUST come from environment variables.
// See appsettings.Docker.json for non-secret defaults.

var caSection = builder.Configuration.GetSection("NipCa");

builder.Services.AddNipCa(opts =>
{
    opts.CaNid            = caSection["CaNid"]
        ?? throw new InvalidOperationException("NipCa:CaNid is required (env: NIPCA__CANID).");

    opts.DisplayName      = caSection["DisplayName"];

    opts.KeyFilePath      = caSection["KeyFilePath"]
        ?? "/data/ca.key.enc";

    opts.KeyPassphrase    = caSection["KeyPassphrase"]
        ?? throw new InvalidOperationException("NipCa:KeyPassphrase is required (env: NIPCA__KEYPASSPHRASE).");

    opts.BaseUrl          = caSection["BaseUrl"]
        ?? throw new InvalidOperationException("NipCa:BaseUrl is required (env: NIPCA__BASEURL).");

    opts.ConnectionString = builder.Configuration.GetConnectionString("Postgres")
        ?? throw new InvalidOperationException("ConnectionStrings:Postgres is required (env: CONNECTIONSTRINGS__POSTGRES).");

    if (int.TryParse(caSection["AgentCertValidityDays"], out var agentDays)) opts.AgentCertValidityDays = agentDays;
    if (int.TryParse(caSection["NodeCertValidityDays"],  out var nodeDays))  opts.NodeCertValidityDays  = nodeDays;
    if (int.TryParse(caSection["RenewalWindowDays"],     out var renewDays)) opts.RenewalWindowDays     = renewDays;

    opts.NormalizeOcspResponseTime = caSection.GetValue("NormalizeOcspResponseTime", true);
    opts.OperatorApiKey            = caSection["OperatorApiKey"]; // env: NIPCA__OPERATORAPIKEY
    opts.AcmeEnabled               = caSection.GetValue("AcmeEnabled", false);
    opts.AcmePathPrefix            = caSection["AcmePathPrefix"] ?? "/acme";
},
generateKeyIfMissing: builder.Environment.IsDevelopment());

builder.Services.AddHealthChecks();

// ── Observability baseline (NPS-Dev #45) ───────────────────────────────────
builder.Services.AddNpsObservability();
builder.Services.AddSingleton<NipCaMetrics>();
builder.Services.AddReadinessProbe("storage", async (sp, ct) =>
{
    var store = sp.GetRequiredService<INipCaStore>();
    try
    {
        // Cheap round-trip — non-existent NID returns null without mutation.
        _ = await store.GetByNidAsync("urn:nps:probe:readyz:nonexistent", ct);
        return null;
    }
    catch (Exception ex)
    {
        return $"ca store unavailable: {ex.Message}";
    }
});
builder.Services.AddReadinessProbe("key_material", (sp, _) =>
{
    var keys = sp.GetService<NipKeyManager>();
    return Task.FromResult<string?>(
        keys is null ? "CA key manager not registered" : null);
});

// ── Build ──────────────────────────────────────────────────────────────────
var app = builder.Build();

app.UseHttpsRedirection();
app.UseShutdownLivenessGate();
app.UseMiddleware<NipCaMetricsMiddleware>();

// /metrics is restricted to the management port (NPS-Dev #58).
// /healthz and /readyz remain reachable on both ports (k8s/LB probes).
var capturedMgmtPort = mgmtPort;
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path == "/metrics" && ctx.Connection.LocalPort != capturedMgmtPort)
    {
        ctx.Response.StatusCode = StatusCodes.Status404NotFound;
        return;
    }
    await next(ctx);
});

// ── Routes ─────────────────────────────────────────────────────────────────
app.UseNipAcme();
app.MapNipCa();
app.MapHealthChecks("/health");
app.MapNpsObservability(
    metricsBearerToken: caSection["MetricsBearerToken"] ?? caSection["OperatorApiKey"],
    requireMetricsBearerToken: true); // /healthz, /readyz, /metrics

// ── Run ────────────────────────────────────────────────────────────────────
app.Run();
