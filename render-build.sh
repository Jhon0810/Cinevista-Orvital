#!/usr/bin/env bash

# Instalar ODBC Driver 18 para SQL Server
apt-get update
apt-get install -y curl gnupg apt-transport-https

# Agregar repositorio de Microsoft para Debian 10
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
curl https://packages.microsoft.com/config/debian/10/prod.list > /etc/apt/sources.list.d/mssql-release.list

apt-get update
ACCEPT_EULA=Y apt-get install -y msodbcsql18 unixodbc-dev
