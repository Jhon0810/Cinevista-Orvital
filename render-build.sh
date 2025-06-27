services:
  - type: web
    name: cinevista-Orvital
    env: python
    buildCommand: |
      # Actualizar el sistema
      apt-get update

      # Instalar dependencias del sistema
      apt-get install -y curl apt-transport-https gnupg lsb-release

      # Agregar repositorio de Microsoft
      curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
      curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list > /etc/apt/sources.list.d/mssql-release.list

      # Actualizar repositorios
      apt-get update

      # Instalar el Driver ODBC 18 para SQL Server y unixODBC
      ACCEPT_EULA=Y apt-get install -y msodbcsql18 unixodbc-dev

      # Instalar dependencias Python del proyecto
      pip install -r requirements.txt

    startCommand: python app.py

    envVars:
      - key: PYTHON_VERSION
        value: 3.11.9
