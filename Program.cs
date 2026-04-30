// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

using NPS.NIP.Extensions;

var builder = WebApplication.CreateBuilder(args);

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
},
generateKeyIfMissing: builder.Environment.IsDevelopment());

builder.Services.AddHealthChecks();

// ── Build ──────────────────────────────────────────────────────────────────
var app = builder.Build();

app.UseHttpsRedirection();

// ── Routes ─────────────────────────────────────────────────────────────────
app.MapNipCa();
app.MapHealthChecks("/health");

// ── Run ────────────────────────────────────────────────────────────────────
app.Run();
