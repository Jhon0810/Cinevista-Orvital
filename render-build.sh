#!/bin/bash

# Actualizar sistema
apt-get update

# Instalar curl y dependencias
apt-get install -y curl apt-transport-https gnupg lsb-release

# Agregar clave de Microsoft
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -

# Agregar repositorio de Microsoft
curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list > /etc/apt/sources.list.d/mssql-release.list

# Actualizar repositorios
apt-get update

# Instalar ODBC Driver 18 para SQL Server
ACCEPT_EULA=Y apt-get install -y msodbcsql18

# Instalar herramientas unixODBC
apt-get install -y unixodbc-dev

# Instalar dependencias de Python
pip install -r requirements.txt