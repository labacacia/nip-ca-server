// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Http;
using NPS.Daemon.Observability.Metrics;

namespace NPS.NipCaServer.Observability;

/// <summary>
/// CA-specific counters surfaced on <c>/metrics</c>: issued, revoked, and
/// rejected CSRs. Counted from response status codes in
/// <see cref="NipCaMetricsMiddleware"/> so the underlying NPS.NIP library
/// stays untouched.
/// </summary>
public sealed class NipCaMetrics
{
    public MetricsRegistry.Counter CertsIssued   { get; }
    public MetricsRegistry.Counter CertsRevoked  { get; }
    public MetricsRegistry.Counter CsrRejected   { get; }

    public NipCaMetrics(MetricsRegistry reg)
    {
        CertsIssued  = reg.RegisterCounter(
            "nip_ca_certs_issued_total",
            "NIP certificates issued (agent / node / orchestrator-group / session).");
        CertsRevoked = reg.RegisterCounter(
            "nip_ca_certs_revoked_total",
            "NIP certificates revoked.");
        CsrRejected  = reg.RegisterCounter(
            "nip_ca_csr_rejected_total",
            "Certificate signing requests rejected (validation, auth, or CA exception).");
    }
}

/// <summary>
/// Classifies CA endpoints into issue / revoke / register-like buckets and
/// updates counters off the response status code. Runs late in the pipeline
/// so it sees the final status after handlers return.
/// </summary>
public sealed class NipCaMetricsMiddleware
{
    private readonly RequestDelegate _next;
    private readonly NipCaMetrics    _metrics;

    public NipCaMetricsMiddleware(RequestDelegate next, NipCaMetrics metrics)
    {
        _next    = next;
        _metrics = metrics;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        await _next(ctx);

        if (ctx.Request.Method != HttpMethods.Post) return;

        var path = ctx.Request.Path.Value ?? "";
        var bucket = Classify(path);
        if (bucket == Bucket.None) return;

        var status = ctx.Response.StatusCode;

        switch (bucket)
        {
            case Bucket.Issue:
                if (status is 200 or 201) _metrics.CertsIssued.Inc();
                else if (status >= 400 && status < 500) _metrics.CsrRejected.Inc();
                break;
            case Bucket.Revoke:
                if (status is 200 or 201) _metrics.CertsRevoked.Inc();
                else if (status >= 400 && status < 500) _metrics.CsrRejected.Inc();
                break;
        }
    }

    private enum Bucket { None, Issue, Revoke }

    private static Bucket Classify(string path)
    {
        // Revoke endpoints (NPS-3 §8 + NPS-CR-0003 §8)
        if (path.EndsWith("/revoke", StringComparison.Ordinal))
        {
            if (path.StartsWith("/v1/agents/",  StringComparison.Ordinal) ||
                path.StartsWith("/v1/nodes/",   StringComparison.Ordinal) ||
                path.StartsWith("/v1/orchestrators/groups/", StringComparison.Ordinal))
                return Bucket.Revoke;
            return Bucket.None;
        }

        // Issue endpoints — anything that mints a fresh IdentFrame or RenewFrame.
        if (path is "/v1/agents/register"        or "/v1/nodes/register"
                  or "/v1/agents/register-x509"  or "/v1/nodes/register-x509"
                  or "/v1/orchestrators/groups/register")
            return Bucket.Issue;

        if (path.StartsWith("/v1/agents/", StringComparison.Ordinal) && path.EndsWith("/renew", StringComparison.Ordinal))
            return Bucket.Issue;
        if (path.StartsWith("/v1/nodes/",  StringComparison.Ordinal) && path.EndsWith("/renew", StringComparison.Ordinal))
            return Bucket.Issue;
        if (path.StartsWith("/v1/orchestrators/groups/", StringComparison.Ordinal) &&
            path.EndsWith("/sessions/issue", StringComparison.Ordinal))
            return Bucket.Issue;

        return Bucket.None;
    }
}
