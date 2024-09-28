AnubisIOCAnalyzer 🛡️🔍

🌟 Descripción General
AnubisIOCAnalyzer es un potente y amigable script en Python diseñado para analizar Indicadores de Compromiso (IOCs) utilizando la API de VirusTotal.

🚀 Características

🔧 Instalación automática de prerrequisitos
🌐 Integración con la API de VirusTotal para un análisis exhaustivo de amenazas
🔍 Soporte para múltiples tipos de IOCs:

🖥️ Direcciones IP
🌐 Dominios
🧬 Hashes de archivos (MD5, SHA1, SHA256)


📊 Generación de informes HTML interactivos
🎨 Interfaz de línea de comandos colorida e intuitiva

📋 Prerrequisitos

Python 3.6+
Kali Linux (recomendado, pero puede adaptarse a otros sistemas)
Clave de API de VirusTotal

🛠️ Instalación

Clona el repositorio:
Copygit clone https://github.com/killluaz/AnubisIOCAnalyzer.git

Navega al directorio del proyecto:
cd AnubisIOCAnalyzer

Ejecuta el script con privilegios de sudo:
sudo python3 anubis_ioc_analyzer.py

Elige la opción 1 del menú para instalar los prerrequisitos automáticamente.

🔑 Configuración
En la primera ejecución, se te pedirá que ingreses tu clave de API de VirusTotal. Esta se guardará en un archivo de configuración para futuros usos.
🚀 Uso

Prepara un archivo de texto con los IOCs que deseas analizar (uno por línea).
Ejecuta el script y selecciona la opción 2 del menú principal.
Proporciona la ruta al archivo de IOCs cuando se te solicite.
El script analizará cada IOC utilizando la API de VirusTotal.
Se generará un informe HTML interactivo con los resultados del análisis.

📊 Ejemplo de Informe
El informe HTML generado incluye:

📌 Resumen de cada IOC analizado
🚦 Nivel de peligro (bajo, medio, alto)
📅 Fecha del último análisis
🌍 Información geográfica (para IPs y dominios)
📁 Detalles del archivo (para hashes)
🔬 Resultados detallados de los motores de análisis

🛡️ Seguridad
Este script está diseñado para ser utilizado por profesionales de seguridad. Asegúrate de tener los permisos necesarios antes de analizar cualquier IOC.

🤝 Contribuciones
Las contribuciones son bienvenidas. Por favor, abre un issue para discutir cambios mayores antes de crear un pull request.

📜 Licencia
Este proyecto está bajo la licencia MIT. Consulta el archivo LICENSE para más detalles.

📞 Contacto
Si tienes preguntas o sugerencias, no dudes en abrir un issue en este repositorio.

Desarrollado por killuaz

🔍 Mantén tus sistemas seguros con AnubisIOCAnalyzer 🛡️
