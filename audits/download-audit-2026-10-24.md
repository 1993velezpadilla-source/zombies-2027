# Auditoría de descargas — ZOMBIES 2027
**Ejecutada:** 24 de octubre de 2026, 03:17 UTC (23 de octubre, Puerto Rico)  
**Repositorio:** 1993velezpadilla-source/zombies-2027  
**Release:** requested-downloads-2026-10-23  
**GitHub Actions:** run 40057019219 — SUCCESS (auditoría estática; RAR necesita contraseña)

## Resumen ejecutivo
- **APK GameHub 6.3.1 — integridad y firma PASS.** Tamaño 67,122,098 bytes; SHA-256 coincidente con GitHub; CRC ZIP válido; certificado V2 con nombre gamesir. Hay permisos potentes que merecen evaluación antes de instalar.
- **RAR de Gofile — integridad externa PASS; auditoría interna BLOQUEADA POR CONTRASEÑA.** 13,143,163,842 bytes, divididos en 11 partes. Cada parte pasó el SHA-256 de GitHub y el RAR reconstruido coincidió exactamente con el SHA-256 original del manifiesto. La cabecera es RAR5 válida. **Al intentar listar los archivos, 7-Zip pidió contraseña; no proporcionamos ninguna y el listado se detuvo.** No conocemos la lista de archivos internos ni se puede concluir que sea seguro o corrupto.
- **Manifiesto JSON — presente y legible.** Se usó para comparar el hash y tamaño del RAR original.

## Inventario de assets del Release
| Componente | Cantidad | Tamaño | Integridad |
|---|---:|---:|---|
| GameHub APK 6.3.1 | 1 | 67,122,098 bytes (67.1 MB) | PASS SHA-256 y CRC |
| Gofile RAR, partes 001–010 | 10 | 1,300,000,000 bytes cada una | PASS SHA-256 |
| Gofile RAR, parte 011 | 1 | 143,163,842 bytes | PASS SHA-256 |
| Manifiesto externo JSON | 1 | 3,279 bytes | Disponible y parseado |
| **RAR unido** | **11 partes** | **13,143,163,842 bytes (13.14 GB)** | **PASS SHA-256 completo** |

### Comprobación criptográfica del RAR
- **Nombre reconstruido:** `yiasuhd6hjxkhbeaAshcuxy2nmpsalk.rar`
- **SHA-256:** `e094a78a769ad8566aa304b13c232427bb770035ece4f678250d9621670e55a3`
- **SHA-256 contra manifiesto original:** COINCIDE
- **Tamaño contra manifiesto original:** COINCIDE
- **Firma/cabecera:** RAR5 reconocible: `52 61 72 21 1a 07 01 00`
- **Listado 7-Zip:** PASSWORD REQUIRED. Mensaje del programa: `Enter password (will not be echoed):`.
- **Archivos, extensiones, directorios, ejecutables o malware internos:** NO AUDITABLES sin la contraseña. No interpretar el inventario vacío como «RAR sin archivos».
- **Extracción/ejecución:** ninguna. No se realizó verificación CRC completa de los archivos internos.

## GameHub Android APK — auditoría del contenido
| Comprobación | Resultado |
|---|---|
| Archivo | `GameHub_6.3.1_0aca596ab937fcb1449dbb7d5700db83.apk` |
| Tamaño | 67,122,098 bytes (67.1 MB) |
| SHA-256 | `09b3e387205215ca0d10fe6881fff034939ae2c16a07b0ce470a48c6c51c6763` |
| ZIP CRC de todos los miembros | PASS |
| Firma criptográfica APK | PASS (APK Signature Scheme v2) |
| ID de paquete | `com.xiaoji.egggame` |
| Versión / versionCode | 6.3.1 / 141 |
| Android mínimo | SDK 29 (Android 10) |
| Android objetivo | SDK 36 (Android 16) |
| Arquitectura nativa | ARM64 (`arm64-v8a`) |
| Archivos internos ZIP | 1,943 |
| Archivos DEX | 5 |
| Bibliotecas nativas `.so` | 25 |
| Certificado declarado | `C=ZHN, ST=guangdong, L=guangzhou, O=gamesir, OU=gamesir, CN=gamesir` |
| SHA-256 del certificado firmante | `f6dc89251d2edf60c5721524d59f2dc6373825a73b1b81d031cafeeff31c9775` |

La firma válida comprueba consistencia con la clave del firmante, **no** confirma por sí sola que el firmante sea el editor oficial. No se ha contrastado esa huella con una publicación independiente del proveedor.

### Permisos de Android para revisar
- `MANAGE_EXTERNAL_STORAGE`: posible acceso amplio a archivos, según versión y autorizaciones Android.
- `REQUEST_INSTALL_PACKAGES`: la app puede pedir al sistema instalar otros paquetes.
- `CAMERA` y `RECORD_AUDIO`: acceso a cámara/micrófono si se conceden permisos.
- `AD_ID`, `ACCESS_ADSERVICES_*`: componentes o funcionalidades publicitarias/medición.
- `INTERNET`, Wi-Fi, Bluetooth, notificaciones y almacenamiento multimedia: permisos habituales en plataformas de gaming/streaming, pero conviene revisar su necesidad.

Los permisos están **declarados**, no significa que todos estén concedidos ni que el APK sea malicioso. El análisis estático no permite decidirlo con certeza.

## Riesgos y limitaciones
1. **RAR bloqueado:** falta la contraseña del archivo para auditar el árbol interno, posibles ejecutables, formatos, datos extraídos, scripts y riesgo de rutas peligrosas. No afirmar que 7-Zip no encontró archivos.
2. **Integridad no equivale a seguridad:** los hashes confirman transferencia fiel, no ausencia de malware.
3. **APK no ejecutado:** no se hizo análisis dinámico, análisis de red, sandbox ni escaneo antimalware. La compatibilidad real con el dispositivo no fue probada.
4. **Repo público:** la redistribución de software/archivos de videojuegos de terceros puede requerir autorización; revisar licencias y condiciones de uso.
5. **Separación del juego Godot:** ambos son assets de GitHub Releases, no código del juego ni una integración automática.

## Evidencias y archivos generados
- `audits/apk-analysis.json` — salida AAPT, permisos, estructura ZIP y firma.
- `audits/rar-inventory.json` — hashes, dimensiones y bloqueo por contraseña.
- `audits/rar-7zip-raw-listing.txt` — prueba literal del prompt de contraseña.
- `manifest-external-downloads.json` — registro original del download dentro de GitHub Release.

**Siguiente dato necesario para terminar la auditoría del RAR:** la contraseña correcta. No desactivamos la protección ni intentamos acceder a archivos protegidos por fuerza bruta.
