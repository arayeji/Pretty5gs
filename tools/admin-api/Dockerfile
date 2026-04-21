FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore Open5gs.AdminApi.sln \
    && dotnet publish src/Open5gs.AdminApi/Open5gs.AdminApi.csproj \
        -c Release \
        -o /app/publish \
        --self-contained true \
        -r linux-x64 \
        /p:PublishSingleFile=true

FROM mcr.microsoft.com/dotnet/runtime-deps:9.0-bookworm-slim AS runtime
WORKDIR /app
COPY --from=build /app/publish/ ./
EXPOSE 9998
ENV DOTNET_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://0.0.0.0:9998
USER 10001:10001
ENTRYPOINT ["/app/open5gs-admin-api"]
