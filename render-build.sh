services:
  - type: web
    name: cinevista-orvital
    env: python
    buildCommand: |
      # Actualizar lista de paquetes
      apt-get update

      # Instalar herramientas necesarias
      apt-get install -y curl apt-transport-https gnupg lsb-release

      # Agregar repositorio de Microsoft para ODBC 18
      curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
      curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list > /etc/apt/sources.list.d/mssql-release.list

      # Actualizar repositorios y agregar EULA
      apt-get update
      ACCEPT_EULA=Y apt-get install -y msodbcsql18 unixodbc-dev

      # Instalar dependencias de Python
      pip install -r requirements.txt

    startCommand: python app.py
    envVars:
      - key: PYTHON_VERSION
        value: 3.11.9