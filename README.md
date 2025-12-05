# CyberCDA: Plataforma de Checklist y Assessment de Ciberseguridad para CDA

CyberCDA es una aplicación web diseñada para ayudar a Centros de Diagnóstico Automotor (CDA) en Colombia a evaluar, gestionar y mejorar su postura de ciberseguridad. Permite importar resultados de escaneos de seguridad (Nmap, OpenVAS), generar controles recomendados por IA, realizar assessments personalizados y monitorear el cumplimiento de controles críticos.

## Características principales

- **Importación de escaneos**: Sube archivos de Nmap, OpenVAS (XML, JSON, PDF) y obtén controles de seguridad generados por IA.
- **Checklist detallado**: Visualiza y gestiona controles de seguridad alineados con estándares (ISO 27001, NIST CSF, OWASP).
- **Assessment personalizado**: Completa una evaluación para adaptar el checklist a las características de tu CDA.
- **Panel de control**: Monitorea el nivel de cumplimiento, alertas críticas y recomendaciones prioritarias.
- **Generación de reportes**: (Próximamente) Exporta reportes en PDF para auditorías y seguimiento.

## Estructura del proyecto

```
├── app.py                  # Aplicación principal Flask
├── requirements.txt        # Dependencias del proyecto
├── checklist_cda.json      # Controles base del checklist
├── assessment.json         # Preguntas y lógica del assessment
├── data/
│   └── scan_results/       # Resultados de escaneos importados
├── static/
│   └── css/styles.css      # Estilos personalizados
├── templates/              # Plantillas HTML (Jinja2)
│   ├── base.html
│   ├── dashboard.html
│   ├── checklist.html
│   ├── assessment.html
│   └── import_scan.html
```

## Instalación

1. **Clona el repositorio**

```bash
git clone <url-del-repo>
cd checklist
```

2. **Crea un entorno virtual y activa**

```bash
python -m venv venv
.\venv\Scripts\activate  # En Windows
# o
source venv/bin/activate  # En Linux/Mac
```

3. **Instala las dependencias**

```bash
pip install -r requirements.txt
```

4. **Configura la clave de OpenAI**

Crea un archivo `.env` en la raíz del proyecto y agrega:

```
OPENAI_API_KEY=tu_clave_openai
```

> **Nota:** El sistema utiliza la API de OpenAI para generar controles a partir de escaneos.

5. **Ejecuta la aplicación**

```bash
python app.py
```

Accede a la aplicación en [http://localhost:5000](http://localhost:5000)

## Uso

- **Importar escaneo**: Ve a "Importar Escaneos", sube un archivo y selecciona el tipo de escaneo.
- **Assessment**: Completa la evaluación para personalizar el checklist.
- **Checklist**: Marca controles implementados y revisa recomendaciones.
- **Dashboard**: Visualiza el estado general y alertas.

## Dependencias principales
- Flask
- openai
- httpx
- PyPDF2
- python-dotenv

(Ver `requirements.txt` para la lista completa)

## Seguridad y privacidad
- Los archivos subidos se procesan localmente y no se almacenan en la nube.
- La clave de OpenAI debe mantenerse privada y segura.

