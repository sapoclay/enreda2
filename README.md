# 🌐 enredA2 - Network Scanner

<div align="right">
<img width="1024" height="1536" alt="splash" src="https://github.com/user-attachments/assets/84f97be3-a46c-4992-9d82-d16eba9e63f7" />
</div>
<div align="center">

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![CustomTkinter](https://img.shields.io/badge/CustomTkinter-5.2.2+-orange.svg)

</div>

---

## 📋 Tabla de Contenidos

- [Descripción](#-descripción)
- [Características](#-características)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Capturas de Pantalla](#-capturas-de-pantalla)
- [Documentación](#-documentación)
- [Arquitectura](#-arquitectura)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)
- [Créditos](#-créditos)

---

## 📖 Descripción

**enredA2** es una aplicación de escritorio profesional para Windows que permite escanear, analizar y gestionar redes locales de forma sencilla e intuitiva. Desarrollada con Python y CustomTkinter, ofrece una interfaz moderna y funcionalidades avanzadas para administradores de sistemas, profesionales de TI y usuarios que necesitan conocer el estado de su red.

### ✨ Principales Ventajas

- 🎨 **Interfaz moderna** con temas claro y oscuro
- 🚀 **Escaneo rápido** con threading para mejor rendimiento
- 🔍 **Análisis profundo** con detección de vulnerabilidades
- 💬 **Mensajería remota** a dispositivos Windows y Linux
- 🔐 **Conexión SSH** directa a dispositivos con puerto 22
- 📊 **Exportación** de resultados a CSV
- 🔔 **Icono de bandeja** para ejecución en segundo plano

---

## ✨ Características

### 🔍 Escaneo de Red

- **Detección automática** de interfaces de red
- **Escaneo personalizado** por rango CIDR
- **Detección de hosts activos** mediante ping
- **Escaneo de puertos** comunes y personalizados
- **Identificación de SO** (Windows, Linux, macOS, etc.)
- **TTL analysis** para mejor detección de sistemas operativos

### 🛡️ Análisis de Seguridad

- **Escaneo profundo** con detección de servicios
- **Análisis de vulnerabilidades** con niveles de severidad
- **Detección de puertos peligrosos** (SMB, RDP, Telnet, etc.)
- **Identificación de tipo de dispositivo** (router, NAS, cámara, servidor)
- **Recomendaciones de seguridad** automáticas
- **Código de colores** para severidad (Crítico, Alto, Medio, Bajo)

### 💬 Sistema de Mensajería

- **Mensajes a Windows** mediante MSG o PowerShell Remoting
- **Mensajes a Linux/Unix** vía SSH (notify-send o wall)
- **Envío múltiple** a varios dispositivos simultáneamente
- **Detección automática** de disponibilidad de mensajería
- **Verificación de puertos** (135, 445, 5985, 22)

### 🔐 Conexión SSH

- **Detección automática** de dispositivos con puerto 22
- **Conexión directa** desde el menú contextual
- **Terminal embebido** o externo (Windows Terminal/PowerShell)
- **Compatibilidad** con dispositivos antiguos (ssh-rsa)
- **Configuración de usuario** personalizable

### 🛠️ Integración Nmap (Opcional)

- **Escaneo avanzado** con Nmap para usuarios experimentados
- **Detección de servicios y versiones**
- **Fingerprinting de SO** más preciso
- **Descubrimiento de hosts** en redes grandes

### 📊 Gestión de Resultados

- **Exportación CSV** de todos los hosts detectados
- **Filtrado en tiempo real** por IP, SO, puertos o estado
- **Cache de resultados** para análisis posterior
- **Historial de escaneos** durante la sesión

### 🎨 Interfaz de Usuario

- **Temas claro y oscuro** personalizables
- **Interfaz responsive** y moderna con CustomTkinter
- **Menú contextual** inteligente según dispositivo
- **Icono de bandeja** para ejecución en segundo plano
- **Diálogos informativos** con guías de solución de problemas
- **Pestañas organizadas** en ventana de preferencias

---

## 💻 Requisitos

### Sistema Operativo

- Windows 10 / 11 (64-bit)
- Ubuntu 22.04
- Permisos de administrador (recomendado para algunas funcionalidades)

### Software

- Python 3.10 o superior
- pip (gestor de paquetes de Python)

### Dependencias Python

```
customtkinter>=5.2.2
pillow>=10.0
python-nmap>=0.7.1
pystray>=0.19.4
```

### Opcional (Funcionalidades Avanzadas)

- **Nmap** - Para escaneos avanzados ([Descargar](https://nmap.org/download.html))
- **OpenSSH Client** - Para conexiones SSH (incluido en Windows 10/11)
- **Windows Terminal** - Para mejor experiencia SSH ([Microsoft Store](https://aka.ms/terminal))

---

## 📥 Instalación

### Método 1: Instalación desde Código Fuente (Recomendado)

1. **Clonar el repositorio**

```bash
git clone https://github.com/tu-usuario/enreda2.git
cd enreda2
```

2. **Crear entorno virtual**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. **Instalar dependencias**

```powershell
pip install -r requirements.txt
```

4. **Ejecutar la aplicación**

```powershell
python run_app.py
```

### Método 2: Instalación rápida

```powershell
# Clonar e instalar en un solo paso
git clone https://github.com/tu-usuario/enreda2.git
cd enreda2
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_app.py
```

### Instalación de Componentes Opcionales

#### Nmap (para escaneos avanzados)

**Opción A - Chocolatey:**
```powershell
choco install nmap
```

**Opción B - Descarga manual:**
- Descargar desde [nmap.org](https://nmap.org/download.html)
- Ejecutar instalador
- Añadir a PATH durante instalación

#### OpenSSH Client (si no está instalado)

```powershell
# Verificar si está instalado
ssh -V

# Si no está, instalar
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

---

## 🚀 Uso

### Inicio rápido

1. **Ejecutar la aplicación**
   ```powershell
   python run_app.py
   ```

2. **Seleccionar interfaz de red** o ingresar rango personalizado (ej: `192.168.1.0/24`)

3. **Hacer clic en "Escanear"**

4. **Esperar resultados** - Los hosts activos aparecerán en la tabla

### Funcionalidades principales

#### Escaneo básico
```
1. Seleccionar red desde el desplegable
2. Clic en "Escanear red seleccionada"
3. Ver resultados en la tabla
```

#### Escaneo profundo
```
1. Clic derecho en un host de la tabla
2. Seleccionar "Escaneo profundo..."
3. Ver análisis de seguridad detallado
```

#### Enviar mensaje
```
1. Clic derecho en un host
2. "Enviar mensaje..." (uno) o "Enviar mensaje a múltiples..." (varios)
3. Escribir mensaje
4. Enviar
```

#### Conectar por SSH
```
1. Clic derecho en host con puerto 22
2. Seleccionar "🔐 Conectar por SSH..."
3. Ingresar usuario
4. Conectar
```

#### Exportar resultados
```
1. Menú → Archivo → Exportar CSV...
2. Elegir ubicación
3. Guardar
```

#### Filtrar resultados
```
1. Usar barra de búsqueda
2. Escribir: IP, SO, puerto o estado
3. Resultados se filtran automáticamente
```

### Configuración

#### Cambiar tema
```
Opciones → Preferencias → Pestaña "🎨 Apariencia" → Seleccionar tema
```

#### Configurar método de mensajería
```
Opciones → Preferencias → Pestaña "💬 Mensajería" → Seleccionar método
```

---

## 📸 Capturas de pantalla

### Ventana principal
<img width="759" height="592" alt="bandeja-principal" src="https://github.com/user-attachments/assets/10000406-088a-40c5-a046-6b3e6e3fe3e3" />


### Escaneo profundo
<img width="892" height="1094" alt="escaneo-profundo" src="https://github.com/user-attachments/assets/6df0f825-0ccb-4cd0-8592-92ac0bbeb255" />


### Mensajería múltiple
<img width="780" height="616" alt="envio-mensajeria-multiple" src="https://github.com/user-attachments/assets/986a2fec-81b8-4df1-ac7f-8365efd4a516" />


### Preferencias
<img width="758" height="591" alt="preferencias" src="https://github.com/user-attachments/assets/333f039d-6c4c-4412-8aa2-1a7cb7f86754" />


---

### Ayuda integrada

La aplicación incluye ayuda contextual:
- **❓ Ayuda de mensajería** - En ventana de envío de mensajes
- **ℹ️ Información** - En ventanas de preferencias y configuración

---

## 🏗️ Arquitectura

### Estructura del proyecto

```
enreda2/
├── run_app.py                       # Punto de entrada (instala dependencias y crea entorno)
├── app.py                           # Aplicación principal y UI
├── menu.py                          # Menú superior (Archivo, Opciones)
├── config.py                        # Gestión de configuración (JSON)
├── requirements.txt                 # Dependencias del proyecto
├── networking/                      # Módulos de red
│   ├── __init__.py
│   ├── scanner.py                   # Escaneo básico de hosts
│   ├── deep_scan.py                 # Escaneo profundo con servicios
│   ├── security_analysis.py         # Análisis de vulnerabilidades
│   ├── messaging.py                 # Sistema de mensajería
│   ├── nmap_integration.py          # Integración con Nmap
│   ├── interfaces.py                # Detección de interfaces
│   ├── ports.py                     # Definición de puertos
│   └── ping.py                      # Utilidades de ping
├── img/                             # Recursos gráficos
│   ├── splash.png                   # Logo de la aplicación
│   └── logo.png                     # Logo alternativo
├── docs/                            # Documentación adicional
│   ├── screenshots/                 # Capturas de pantalla
│   └── guides/                      # Guías detalladas
└── .venv/                           # Entorno virtual (generado)
```

### Tecnologías Utilizadas

- **[CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)** - Framework UI moderno
- **[Pillow](https://python-pillow.org/)** - Procesamiento de imágenes
- **[python-nmap](https://pypi.org/project/python-nmap/)** - Wrapper de Nmap
- **[pystray](https://pypi.org/project/pystray/)** - Icono de bandeja del sistema
- **Threading** - Ejecución concurrente de escaneos
- **Socket** - Comunicación de red de bajo nivel
- **Subprocess** - Ejecución de comandos del sistema

### Patrones de diseño

- **MVC** - Separación de lógica de negocio y presentación
- **Observer** - Actualización de UI mediante colas
- **Factory** - Creación de diálogos y ventanas
- **Singleton** - Gestión de configuración global

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Si deseas mejorar el proyecto:

### Cómo contribuir

1. **Fork** del repositorio
2. **Crear rama** de característica (`git checkout -b feature/AmazingFeature`)
3. **Commit** de cambios (`git commit -m 'Add some AmazingFeature'`)
4. **Push** a la rama (`git push origin feature/AmazingFeature`)
5. **Abrir Pull Request**

### Guías de contribución

- Seguir el estilo de código existente (PEP 8)
- Añadir documentación para nuevas funcionalidades
- Incluir tests si es posible
- Actualizar el CHANGELOG.md
- Asegurar que el código funciona en Windows 10/11

### Reportar bugs

Usa la sección [Issues](https://github.com/tu-usuario/enreda2/issues) para reportar bugs. Incluye:

- Descripción del problema
- Pasos para reproducir
- Comportamiento esperado vs actual
- Versión de Python y SO
- Logs o capturas de pantalla

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.

---

## 👏 Créditos

### Desarrollador

- **Creado por**: [entreunosyceros.net](https://entreunosyceros.net)

### Agradecimientos

- **[CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)** - Por el excelente framework de UI
- **[Nmap](https://nmap.org/)** - Por la herramienta de escaneo de red
- **Comunidad Python** - Por las increíbles bibliotecas y herramientas

### Bibliotecas de Terceros

- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) - UI Framework
- [Pillow](https://python-pillow.org/) - Procesamiento de imágenes
- [python-nmap](https://pypi.org/project/python-nmap/) - Wrapper de Nmap
- [pystray](https://pypi.org/project/pystray/) - System tray icon

---

## 📞 Soporte

### Recursos de Ayuda

- **Documentación** - Ver archivos `.md` en el proyecto
- **Issues** - [GitHub Issues](https://github.com/sapoclay/enreda2/issues)
- **Discusiones** - [GitHub Discussions](https://github.com/sapoclay/enreda2/discussions)

### Contacto

- **Web**: [entreunosyceros.net](https://entreunosyceros.net)
- **GitHub**: [@sapoclay](https://github.com/sapoclay)

---

## ⚠️ Descargo de Responsabilidad

Esta herramienta está diseñada para uso legítimo en redes de tu propiedad o con autorización explícita. El escaneo de redes sin permiso puede ser ilegal en tu jurisdicción.

**IMPORTANTE:**
- Solo escanea redes de tu propiedad
- Obtén autorización por escrito antes de escanear redes de terceros
- El uso indebido de esta herramienta es responsabilidad exclusiva del usuario
- Los desarrolladores no se responsabilizan por el mal uso de esta aplicación

---

## 🌟 Estado del Proyecto

![Status](https://img.shields.io/badge/status-active-success.svg)
![Maintenance](https://img.shields.io/badge/maintained-yes-green.svg)

**Última actualización**: Noviembre 2025

### Versión Actual: 2.0

**Características principales:**
- ✅ Escaneo de red completo
- ✅ Análisis de seguridad
- ✅ Sistema de mensajería multiplataforma
- ✅ Conexión SSH directa
- ✅ Exportación CSV
- ✅ Icono de bandeja del sistema
- ✅ Integración Nmap opcional

---

<div align="center">

[⬆ Volver arriba](#-enreda2---network-scanner)

</div>

