[README.md](https://github.com/user-attachments/files/33934205/README.md)
# Informe Técnico – RootMe (TryHackMe)

> **Sala:** [TryHackMe – RootMe](https://tryhackme.com/room/rrootme)
> **Dificultad:** Fácil
> **Estado:** Completado  (flags de usuario y root obtenidas; no se exponen en texto plano — ver sección de evidencias)

---

## 1. Objetivo y descripción del laboratorio

RootMe es una máquina de dificultad introductoria en TryHackMe orientada a practicar el
flujo completo de un pentest básico sobre una aplicación web Linux: reconocimiento de
servicios, explotación de una vulnerabilidad de subida de archivos (*unrestricted file
upload*) para lograr ejecución remota de comandos, y escalada de privilegios local hasta
obtener acceso como `root`.

**Objetivos concretos del laboratorio:**
- Identificar los servicios y tecnologías expuestas por el host objetivo.
- Obtener ejecución remota de comandos (RCE) a través de la aplicación web.
- Escalar privilegios de `www-data` a `root`.
- Capturar las flags `user.txt` y `root.txt` como prueba de éxito.

## 2. Herramientas utilizadas

| Herramienta | Propósito |
|---|---|
| `nmap` | Escaneo de puertos, servicios y detección de SO |
| `gobuster` | Enumeración de directorios y rutas web |
| Firefox (navegador) | Interacción con el panel de subida de archivos |
| `php-reverse-shell.php` (pentestmonkey) | Payload de shell inversa en PHP |
| `nc` (netcat) | Listener para recibir la conexión inversa |
| `python3` / `pty` | Estabilización de la shell (TTY completo) |
| `find` | Búsqueda de binarios con bit SUID |
| `python` (binario SUID, GTFOBins) | Vector de escalada de privilegios a root |

## 3. Metodología

### 3.1 Reconocimiento inicial

Máquina atacante: `10.64.189.39` · Máquina objetivo: `10.64.158.8`

*(Evidencia: `evidencias/01-maquinas-activas.png`)*

```bash
nmap -A -Pn -T5 10.64.158.8
```

**Resultado:**

| Puerto | Estado | Servicio | Versión |
|---|---|---|---|
| 22/tcp | open | ssh | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 |
| 80/tcp | open | http | Apache httpd 2.4.41 (Ubuntu) |

El título de la página web es **"HackIT - Home"**, y la cabecera `PHPSESSID` confirma que el
backend está escrito en PHP. El sistema operativo detectado corresponde a una distribución
Linux (kernel de la familia 3.x–5.x según las huellas de `nmap`).

*(Evidencia: `evidencias/02-nmap-scan.png`)*

### 3.2 Enumeración web

```bash
gobuster dir -u http://10.64.158.8 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Resultado:**

| Ruta | Status | Tamaño |
|---|---|---|
| `/uploads` | 301 | 312 |
| `/css` | 301 | 308 |
| `/js` | 301 | 307 |
| `/panel` | 301 | 310 |
| `/server-status` | 403 | 276 |

La ruta `/panel/` resultó ser la más relevante: contiene un formulario de **subida de
archivos**, y `/uploads/` es, previsiblemente, el directorio donde se almacenan los archivos
subidos (posible ejecución directa de scripts si no está correctamente aislado).

*(Evidencia: `evidencias/03-gobuster.png`, `evidencias/04-panel-upload.png`)*

### 3.3 Explotación – Subida de archivos insegura (Unrestricted File Upload)

**Descripción de la vulnerabilidad:**
El formulario en `/panel/` permite subir archivos sin una validación robusta del tipo de
contenido. El filtro del lado del servidor rechaza la extensión `.php`, pero **no contempla
extensiones alternativas que Apache, con `mod_php`, también interpreta como PHP ejecutable**
(en este caso, `.phtml`). Esto constituye una lista negra incompleta en lugar de una lista
blanca, permitiendo evadir la restricción.

**Pasos de explotación:**

1. Se obtuvo el payload clásico `php-reverse-shell.php` (pentestmonkey), configurado con la
   IP y puerto del atacante.
2. Se renombró el archivo a `shell.phtml` para evadir el filtro de extensiones del formulario.

   *(Evidencia: `evidencias/05-preparacion-shell-phtml.png`)*

3. Se subió el archivo a través del panel web, confirmando el mensaje *"O arquivo foi upado
   com sucesso!"*.

   *(Evidencia: `evidencias/06-upload-exitoso.png`)*

4. Se puso en escucha un listener de `netcat`:

   ```bash
   nc -lvnp 1234
   ```

5. Se accedió al archivo subido desde `/uploads/shell.phtml`, lo que disparó la ejecución
   del payload PHP y entregó una shell inversa como el usuario del servicio web (`www-data`).

   *(Evidencia: `evidencias/07-reverse-shell-www-data.png`)*

   ```
   uid=33(www-data) gid=33(www-data) groups=33(www-data)
   ```

6. Se estabilizó la shell con:

   ```bash
   python3 -c 'import pty;pty.spawn("/bin/bash")'
   ```

   y se localizó la flag de usuario:

   ```bash
   find / -type f -name user.txt 2>/dev/null
   # /var/www/user.txt
   cat /var/www/user.txt
   ```

   *(Evidencia: `evidencias/08-shell-estabilizada-user-txt.png`, flag redactada en
   `evidencias/09-flag-usuario-redactada.png`)*

**Condiciones que permitieron la explotación:**
- Validación de archivos basada únicamente en la extensión, con una lista negra incompleta
  que no cubre todas las extensiones que el intérprete PHP/Apache reconoce como ejecutables
  (`.phtml`, `.php5`, `.pht`, etc.).
- Ausencia de verificación del contenido/tipo MIME real del archivo subido.
- El directorio de subidas permite la **ejecución** de scripts, no solo su almacenamiento.

**Impacto en un entorno real:**
Ejecución remota de comandos (RCE) con los privilegios del servicio web. Un atacante podría
leer y modificar archivos de la aplicación, acceder a credenciales de configuración (bases de
datos, claves de API), desplegar malware o web shells persistentes, y usar el servidor
comprometido como punto de pivote hacia la red interna.

### 3.4 Escalada de privilegios – Binario SUID mal configurado

**Descripción de la vulnerabilidad:**
Tras obtener acceso como `www-data`, se buscaron binarios con el bit SUID activo:

```bash
find / -perm -4000 2>/dev/null
```

Entre los resultados (la mayoría binarios del sistema esperables, como `/usr/bin/sudo`,
`/usr/bin/passwd`, `/usr/bin/pkexec`), destacó uno que **no debería tener SUID en una
configuración segura**: `/usr/bin/python2.7`.

*(Evidencia: `evidencias/10-busqueda-suid.png`)*

Según [GTFOBins](https://gtfobins.github.io/gtfobins/python/#suid), un binario de Python con
bit SUID permite generar directamente una shell con los privilegios del propietario del
binario (root), ya que Python puede invocar llamadas al sistema (`os.execl`) heredando ese
permiso elevado.

**Pasos de explotación:**

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

El flag `-p` preserva los privilegios efectivos del proceso (necesario porque `/bin/sh`
normalmente descarta privilegios SUID al iniciar si no se preservan explícitamente).

```bash
whoami
# root
```

*(Evidencia: `evidencias/11-escalada-root.png`)*

Finalmente, se localizó y leyó la flag de root:

```bash
find / -type f -name root.txt 2>/dev/null
# /root/root.txt
cat /root/root.txt
```

*(Evidencia: flag redactada en `evidencias/12-flag-root-redactada.png`)*

**Condiciones que permitieron la explotación:**
- Asignación innecesaria del bit SUID a un intérprete de propósito general (Python), que por
  diseño permite ejecutar código y llamadas al sistema arbitrarias.
- Ausencia de una política de mínimo privilegio sobre los binarios del sistema.
- No existía ningún control de auditoría (ej. `lynis`, `linpeas`) que hubiera detectado esta
  configuración antes de ser explotada.

**Impacto en un entorno real:**
Compromiso total del host (root). Un atacante con esta capacidad puede instalar puertas
traseras persistentes, crear nuevos usuarios con privilegios, desactivar controles de
seguridad, acceder a cualquier dato almacenado en el sistema y usar la máquina como pivote
para comprometer otros sistemas de la red.

## 4. Vulnerabilidades encontradas – resumen

| # | Vulnerabilidad | Severidad | Vector | Resultado |
|---|---|---|---|---|
| 1 | Subida de archivos sin validación adecuada (Unrestricted File Upload) → RCE | Alta | Formulario web `/panel/` | Shell como `www-data` |
| 2 | Binario `python2.7` con bit SUID mal configurado | Crítica | Escalada de privilegios local | Shell como `root` |

## 5. Remediaciones recomendadas

### Para la subida de archivos insegura
- Reemplazar la lista negra de extensiones por una **lista blanca estricta** (ej. solo
  `.jpg`, `.png`, `.pdf`, según el caso de uso del formulario).
- Validar el **contenido real del archivo** (magic bytes / tipo MIME con librerías como
  `finfo` en PHP), no solo el nombre o la extensión declarada.
- Servir el directorio de subidas **sin permisos de ejecución de scripts**
  (en Apache: `php_admin_flag engine off` dentro de un bloque `<Directory>` para `/uploads/`,
  o mover ese directorio fuera de la raíz web / `DocumentRoot`).
- Renombrar los archivos subidos a un identificador aleatorio sin extensión controlada por
  el usuario.
- Añadir un WAF (Web Application Firewall) como capa adicional de defensa en profundidad.

### Para la escalada de privilegios vía SUID
- Auditar periódicamente los binarios con bit SUID/SGID (`find / -perm -4000 -o -perm -2000
  2>/dev/null`) y remover el bit de aquellos que no lo requieran explícitamente
  (`chmod u-s /usr/bin/python2.7`).
- Nunca asignar SUID a intérpretes de propósito general (Python, Perl, Bash, etc.): si se
  necesita que un script específico corra con privilegios elevados, usar `sudo` con reglas
  acotadas en `/etc/sudoers` (comando exacto, sin shell interactiva) en lugar de SUID sobre
  el intérprete completo.
- Aplicar el **principio de mínimo privilegio** en toda la configuración del sistema.
- Incorporar herramientas de auditoría automatizada (`lynis`, `linpeas`, `pspy`) en el
  proceso de hardening y en revisiones periódicas.

## 6. Conclusiones y aprendizajes

Este laboratorio permitió recorrer de principio a fin la cadena de ataque típica de una
aplicación web mal configurada: un control de subida de archivos aparentemente presente
(bloquea `.php`) resultó insuficiente por no contemplar extensiones equivalentes que el
propio servidor interpreta igual (`.phtml`), lo que demuestra que las listas negras son
inherentemente frágiles frente a las listas blancas. Asimismo, la fase de post-explotación
reforzó la importancia de auditar sistemáticamente los permisos SUID del sistema, ya que un
solo binario mal configurado (`python2.7`) fue suficiente para escalar de un usuario de
servicio sin privilegios a `root` de forma inmediata.

El aprendizaje principal es que la seguridad de una aplicación no depende de un único
control, sino de múltiples capas: validación de entrada en la aplicación, configuración
segura del servidor web, y una política estricta de mínimo privilegio a nivel de sistema
operativo. La ausencia de cualquiera de estas capas puede convertir una vulnerabilidad de
severidad media (subida de archivos) en un compromiso total del sistema.

---

## Evidencias

Todas las capturas se encuentran en la carpeta [`evidencias/`](./evidencias). Las imágenes
que mostraban el contenido completo de las flags fueron **redactadas** antes de su
publicación, conservando el comando y el contexto como prueba de su obtención sin exponer
su valor real.

| Archivo | Contenido |
|---|---|
| `01-maquinas-activas.png` | IPs de la máquina atacante y objetivo |
| `02-nmap-scan.png` | Escaneo de puertos y servicios (`nmap -A`) |
| `03-gobuster.png` | Enumeración de directorios web |
| `04-panel-upload.png` | Formulario de subida de archivos (`/panel/`) |
| `05-preparacion-shell-phtml.png` | Renombrado de la web shell a `.phtml` |
| `06-upload-exitoso.png` | Confirmación de subida exitosa |
| `07-reverse-shell-www-data.png` | Shell inversa recibida como `www-data` |
| `08-shell-estabilizada-user-txt.png` | Shell estabilizada y ubicación de `user.txt` |
| `09-flag-usuario-redactada.png` | Lectura de `user.txt` (flag redactada) |
| `10-busqueda-suid.png` | Búsqueda de binarios SUID, incluye `python2.7` |
| `11-escalada-root.png` | Explotación del SUID y confirmación de `root` |
| `12-flag-root-redactada.png` | Lectura de `root.txt` (flag redactada) |

## Aviso de responsabilidad

Este informe documenta actividades realizadas exclusivamente dentro del entorno autorizado
de TryHackMe con fines educativos. No se incluyen credenciales, tokens ni el contenido
completo de las flags obtenidas, conforme a las consideraciones de la actividad.
