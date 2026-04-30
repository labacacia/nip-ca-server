# ── Build stage ───────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore (layer-cached). The publish repo is self-contained: only the
# .csproj here, and the LabAcacia.NPS.NIP NuGet package pulled from
# nuget.org per nuget.config.
COPY NPS.NipCaServer.csproj ./
COPY nuget.config           ./

RUN dotnet restore NPS.NipCaServer.csproj --configfile nuget.config

# Copy source and publish.
COPY Program.cs              ./
COPY appsettings.json        ./
COPY appsettings.Docker.json ./

RUN dotnet publish NPS.NipCaServer.csproj \
    -c Release \
    -o /app/publish \
    --no-restore

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# Non-root user for security.
RUN addgroup --gid 1001 nipca && adduser --uid 1001 --gid 1001 --disabled-password --gecos "" nipca

# Data directory for the encrypted CA key file (mount as a volume).
RUN mkdir -p /data && chown nipca:nipca /data

COPY --from=build /app/publish .
RUN chown -R nipca:nipca /app

USER nipca

# Default NIP port (NPS-3 §1).
EXPOSE 17435

ENV ASPNETCORE_ENVIRONMENT=Docker
ENV ASPNETCORE_URLS=http://0.0.0.0:17435

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:17435/health || exit 1

ENTRYPOINT ["dotnet", "NPS.NipCaServer.dll"]
