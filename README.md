# AURA — MVP Funcional (HealthTech Innovations)

![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![Auth](https://img.shields.io/badge/Auth-OAuth2%20%2B%20RBAC-EF4444)
![License](https://img.shields.io/badge/license-MIT-22C55E)
![Status](https://img.shields.io/badge/status-MVP-F5A623)

> Proyecto académico — GPY1101 Evaluación de Proyectos de Software (Duoc UC).
> Gestión unificada de proyectos con detección y rebalanceo de carga de equipos.

MVP de la **Opción B (Desarrollo Iterativo por Módulos)**. Implementa el
**requerimiento funcional principal**: detectar equipos **sobrecargados** y
**subutilizados** y **sugerir un rebalanceo** de la carga de trabajo, que es el
dolor central del caso (35% de equipos sobrecargados, 25% subutilizados, 70% de
proyectos con retraso), **protegido con autenticación y control de acceso por roles**.

> Alcance del MVP: cubre la funcionalidad crítica + una capa de **seguridad**
> alineada a HIPAA/GDPR (acceso a datos sensibles bajo mínimo privilegio).
> No incluye la integración con los sistemas legados de cada sede (eso forma
> parte del sistema completo, no del MVP).

## Stack
- **Python 3** + **FastAPI** (backend y API REST)
- **OAuth2 (Bearer token)** + **PBKDF2-HMAC-SHA256** para el hash de contraseñas
- **HTML + JavaScript** (dashboard, sin framework para mantenerlo simple)
- Almacenamiento **en memoria** (sin base de datos) para un MVP demostrable

## Seguridad (alineada a HIPAA/GDPR)
- **Contraseñas hasheadas** con PBKDF2-HMAC-SHA256 + salt único (120.000 iteraciones); nunca se almacenan en texto plano.
- **Autenticación por token Bearer (OAuth2)** con **expiración de sesión** (30 min).
- **Control de acceso por roles (RBAC)** — principio de **mínimo privilegio**:
  - `admin` → acceso total · `gerente` → puede asignar proyectos · `lector` → solo lectura.
- Todos los endpoints de datos requieren un token válido; asignar proyectos exige rol admin/gerente.

### Usuarios de prueba
| Usuario | Contraseña | Rol | Permisos |
|---------|-----------|-----|----------|
| admin | admin123 | admin | Todo |
| gerente | gerente123 | gerente | Ver + asignar proyectos |
| lector | lector123 | lector | Solo lectura |

## Cómo ejecutar
```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Levantar el servidor
uvicorn main:app --reload

# 3. Abrir en el navegador
http://127.0.0.1:8000
```
La documentación interactiva de la API queda en `http://127.0.0.1:8000/docs`.

## Qué hace
1. Muestra la **carga de cada equipo** (horas asignadas / capacidad) con color:
   rojo = sobrecargado (>85%), dorado = subutilizado (<60%), verde = OK.
2. Calcula **KPIs**: equipos sobrecargados, subutilizados y balanceados.
3. Genera **sugerencias de rebalanceo** (mover horas del sobrecargado al libre).
4. Permite **asignar un nuevo proyecto** a un equipo y recalcula todo en vivo.

## Endpoints (API REST)
| Método | Ruta | Acceso | Descripción |
|--------|------|--------|-------------|
| GET | `/` | público | Pantalla de login + dashboard |
| POST | `/api/login` | público | Valida credenciales y entrega token |
| POST | `/api/logout` | autenticado | Cierra la sesión (invalida el token) |
| GET | `/api/analisis` | autenticado | Análisis de carga + sugerencias (JSON) |
| GET | `/api/equipos` | autenticado | Lista de equipos |
| POST | `/api/proyectos` | admin/gerente | Crea proyecto `{nombre, equipo, horas}` y recalcula |

## Lógica de negocio (clave)
```python
UMBRAL_SOBRECARGA   = 0.85   # > 85% de capacidad => SOBRECARGADO
UMBRAL_SUBUTILIZADO = 0.60   # < 60% de capacidad => SUBUTILIZADO
uso = horas_asignadas / capacidad
```
El motor (`analizar()` en `main.py`) recorre los equipos, los clasifica y mueve
el exceso de los sobrecargados hacia los que tienen holgura.

## Decisiones técnicas (para la defensa)
- **FastAPI**: coherente con la alternativa elegida; API REST tipada y `/docs` automático.
- **OAuth2 + PBKDF2**: estándar de la industria para autenticación; PBKDF2 evita guardar contraseñas en texto plano.
- **RBAC (mínimo privilegio)**: cada rol ve solo lo que necesita, requisito clave de HIPAA/GDPR.
- **En memoria**: el MVP prioriza demostrar la lógica crítica; la versión final usaría PostgreSQL.
- **Frontend sin framework**: minimiza dependencias y facilita la revisión del código.

## Limitaciones actuales (vs sistema completo)
- Datos y sesiones en memoria (se reinician al reiniciar el servidor); la versión final usaría PostgreSQL + Redis y tokens JWT firmados.
- Sin integración con los sistemas legados de cada sede.
- Rebalanceo sugerido (no automático): la decisión final la toma el gerente.
