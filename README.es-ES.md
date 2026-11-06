

# SMX - Implementación Multilingüe de Algoritmos Criptográficos Nacionales

[中文](README.md) | [English](README.en-US.md) | Español

> **Esta es la rama `security` (alta seguridad):** SM4 es de tiempo constante. Para la versión de alto rendimiento cambie a `main`; vea «Elegir versión» más abajo.

Basado completamente en los estándares de algoritmos criptográficos comerciales publicados por la Administración Estatal de Criptografía, esta implementación logra la aplicación integral de los algoritmos criptográficos nacionales SM2, SM3 y SM4 en ocho lenguajes de programación principales: **Java, JavaScript, Swift, Rust, Go, C, C# y Python**, con **cero dependencias de terceros**.

Todas las implementaciones siguen estrictamente las especificaciones algorítmicas y los casos de prueba publicados por la Administración Estatal de Criptografía. La salida de los algoritmos coincide completamente con los estándares de prueba oficiales, por lo que pueden aplicarse directamente al desarrollo y despliegue de productos de criptografía comercial.

## Elegir versión: alto rendimiento o alta seguridad

Este repositorio ofrece dos ramas. **Los algoritmos, la API y las salidas son idénticos, de modo que ambas versiones se comunican entre sí y descifran los datos de la otra.** Solo cambia la implementación interna de SM4:

| Rama | Implementación de SM4 | Uso recomendado |
|---|---|---|
| `main` (alto rendimiento, por defecto) | Basada en tablas, como OpenSSL y BouncyCastle; la más rápida | Servidores y cualquier entorno donde ningún código no confiable comparta la misma CPU |
| `security` (alta seguridad) | Tiempo constante, sin accesos a tablas que dependan de la clave; SM4 más lento | Clientes (apps, programas de escritorio, navegadores) y nubes donde la CPU física se comparte con otros inquilinos |

Fuera de SM4, el código de ambas ramas es el mismo: el SM2 de tiempo constante, el generador de números aleatorios seguro y la validación estricta de entradas están en las dos.

**Alto rendimiento no significa inseguro.** Una implementación con tablas está expuesta a ataques de temporización de caché: el atacante no lee su memoria, sino que ejecuta su propio programa en **la misma máquina y la misma CPU**, mide cuánto tardan sus propios accesos a memoria y deduce qué entradas de la tabla usó el cifrado, y de ahí la clave. Por tanto:

- **En un servidor que usted controla** y que solo ejecuta sus servicios, el atacante no puede ejecutar código en la misma CPU, así que este ataque prácticamente no tiene por dónde empezar. Medir tiempos a través de la red es posible en teoría, pero exige una cantidad enorme de mediciones precisas y en la práctica es muy difícil. El SM4 de OpenSSL en ARM y otras plataformas también usa tablas y se emplea ampliamente en servidores.
- **En un cliente**, el mismo dispositivo puede ejecutar a la vez apps o scripts web no confiables que comparten la caché de la CPU con su código criptográfico, y el riesgo es claramente mayor.
- **En una nube con CPU física compartida**, otros inquilinos del mismo anfitrión podrían, en teoría, lanzar este ataque. Usar núcleos físicos dedicados o anfitriones dedicados lo evita.

Una aclaración más: si un atacante ya puede leer directamente la memoria de su proceso, la clave queda expuesta y ninguna de las dos versiones lo impide; no es algo que se resuelva eligiendo rama.

Para obtener la versión de alta seguridad:

```bash
git clone -b security https://github.com/aicccode/smx.git
```

## Matriz de funcionalidades

| Funcionalidad | Java | JavaScript | Swift | Rust | Go | C | C# | Python |
|------|:----:|:----------:|:-----:|:----:|:--:|:-:|:--:|:------:|
| Hash SM3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cifrado/Descifrado Simétrico SM4 (CBC/PKCS7) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cifrado/Descifrado Asimétrico SM2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Firma Digital / Verificación SM2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Intercambio de Claves SM2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## Estructura del proyecto

```
smx/
├── java/            # Implementación Java (Maven, site.aicc:gm-java)
├── javascript/      # Implementación JavaScript (npm, ES Module)
├── swift/           # Implementación Swift (SwiftPM, GMSwift)
├── rust/            # Implementación Rust (Cargo, gm-rust)
├── go/              # Implementación Go (Go Module, smx)
├── c/               # Implementación C (Makefile, C99)
├── csharp/          # Implementación C# (.NET 8, SMX)
├── python/          # Implementación Python (pyproject, gm-python)
├── demo/            # Demo de intercambio de claves y comunicación cifrada entre lenguajes
│   ├── server-java/     # Servidor HTTP Java (Lado B)
│   ├── client-js/       # Cliente JavaScript (Lado A)
│   ├── client-rust/     # Cliente Rust (Lado A)
│   ├── client-swift/    # Cliente Swift (Lado A)
│   ├── client-go/       # Cliente Go (Lado A)
│   ├── client-c/        # Cliente C (Lado A, libcurl)
│   ├── client-csharp/   # Cliente C# (Lado A, .NET 8)
│   ├── client-python/   # Cliente Python (Lado A)
│   └── run-tests.sh     # Script de prueba rápida
└── doc/             # Documentos de especificación algorítmica (PDF)
```

## Implementaciones por lenguaje

### Java

```bash
cd java
mvn test        # Ejecutar pruebas
mvn install     # Instalar en el repositorio local
```

- **Herramienta de compilación:** Maven
- **Nombre del paquete:** `site.aicc` (`gm-java:1.0.0`)
- **Versión mínima:** Java 8+
- **Dependencias:** Ninguna (solo JUnit para pruebas)

### JavaScript

```bash
cd javascript
npm test        # Ejecutar pruebas
```

- **Herramienta de compilación:** npm (ES Module)
- **Nombre del paquete:** `gm-js`
- **Entorno de ejecución:** Node.js (ES Module)
- **Dependencias:** Ninguna

### Swift

```bash
cd swift
swift test      # Ejecutar pruebas
swift build     # Compilar
```

- **Herramienta de compilación:** Swift Package Manager
- **Nombre de la biblioteca:** `GMSwift`
- **Versión mínima:** Swift 5.7+, iOS 15+, macOS 10.13+
- **Dependencias:** Ninguna

### Rust

```bash
cd rust
cargo test      # Ejecutar pruebas
cargo build     # Compilar
```

- **Herramienta de compilación:** Cargo
- **Nombre del paquete:** `gm-rust`
- **Versión mínima:** Rust 1.85 (edición 2024)
- **Dependencias:** Ninguna

### Go

```bash
cd go
go test ./...   # Ejecutar pruebas
```

- **Herramienta de compilación:** Go Modules
- **Nombre del módulo:** `smx`
- **Versión mínima:** Go 1.21+
- **Dependencias:** Ninguna

### C

```bash
cd c
make test       # Compilar y ejecutar pruebas
```

- **Herramienta de compilación:** Makefile (gcc)
- **Estándar:** C99
- **Dependencias:** Ninguna (biblioteca principal), libcurl (solo cliente de demo)

### C#

```bash
cd csharp
dotnet test     # Ejecutar pruebas
dotnet build    # Compilar
```

- **Herramienta de compilación:** .NET SDK
- **Nombre de la biblioteca:** `SMX`
- **Versión mínima:** .NET 8.0
- **Dependencias:** Ninguna (solo xunit para pruebas)

### Python

```bash
cd python
python3 -m unittest discover -s tests -t .   # Ejecutar pruebas (sin instalar dependencias)
python3 -m pytest                            # También se puede ejecutar con pytest
SMX_SLOW_TESTS=1 python3 -m unittest discover -s tests -t .   # Incluye las pruebas lentas de SM3 de 512 MiB/1 GiB
```

- **Herramienta de compilación:** setuptools (pyproject.toml)
- **Nombre del paquete:** `gm-python` (se importa como `smx`)
- **Versión mínima:** Python 3.9+
- **Dependencias:** Ninguna (pytest opcional, solo para pruebas)

## Notas de seguridad

### Requisitos de entrada

- **La clave y el IV de SM4 deben tener exactamente 16 bytes** (o 32 dígitos hexadecimales). Las versiones anteriores convertían "claves de texto" de otras longitudes mediante hash o truncamiento, con una fortaleza real de unos 64 bits; ahora se rechazan con un error. Los datos cifrados con esas claves no se pueden descifrar con la versión nueva: descífrelos con la versión anterior y vuelva a cifrarlos.
- **El hexadecimal de firmas y textos cifrados debe estar en minúsculas**, igual que la salida de la biblioteca, para que cada firma tenga una única representación. El hexadecimal de las claves pública y privada sigue sin distinguir mayúsculas.
- Las entradas inválidas (puntos fuera de la curva, claves o firmas fuera de rango, longitudes incorrectas, relleno erróneo, etc.) producen un error o un fallo según la convención de cada lenguaje. La API pública de cada lenguaje se ha probado con fuzzing sin encontrar caídas ni bloqueos, aunque el fuzzing no demuestra que no existan.

### Limitaciones de SM4-CBC

- **CBC solo ofrece confidencialidad, no integridad.** Un texto cifrado puede modificarse sin que se detecte. Si necesita integridad, añada un MAC (por ejemplo HMAC-SM3) y verifíquelo antes de descifrar.
- **Un mismo objeto SM4 usa el mismo IV en cada cifrado después de fijar la clave.** Un mismo texto claro produce el mismo texto cifrado. Use un IV aleatorio nuevo para cada mensaje.
- El descifrado que devuelve una cadena valida el UTF-8, y esa validación sigue dependiendo del contenido. Para datos binarios o requisitos de tiempo más estrictos, use las funciones de descifrado que devuelven bytes.

### Canales laterales

- En SM2, las operaciones con la clave privada (generación de claves, firma, descifrado, intercambio de claves) usan ventanas fijas y selección enmascarada en tablas, sin ramas ni direcciones de memoria que dependan de datos secretos. C, Rust y Swift incluyen herramientas que revisan el código compilado (`make check-ct` en C, `rust/tools/check_ct_asm.py`, `swift/Tools/check_constant_time.py`); vuelva a ejecutarlas al cambiar de compilador.
- **En esta rama (`security`), SM4 no usa tablas indexadas por datos secretos**: utiliza AES-NI, GFNI o las instrucciones AES de ARM cuando existen y, si no, una S-box implementada como circuito booleano. En la rama `main`, SM4 usa tablas: es más rápido, pero no resiste ataques de temporización de caché; vea «Elegir versión» más arriba.
- Java, C#, JavaScript y Python se ejecutan en entornos gestionados que no garantizan tiempo constante; la biblioteca solo puede evitar en el código fuente las ramas y los accesos a tablas que dependen de secretos (en SM2; en la rama `security`, también en SM4).
- La verificación de firmas solo maneja datos públicos y usa algoritmos de tiempo variable por velocidad.

### Claves antiguas que deben sustituirse

Las claves generadas con versiones anteriores en estos entornos usaban una fuente aleatoria insegura y **deben sustituirse**; las firmas antiguas hechas con ellas tampoco deben considerarse fiables:

- JavaScript en Node.js 18 o anterior: el azar venía por completo de `Math.random`
- JavaScript en navegadores o Node.js 20 o posterior: mezclaba `Math.random` y RC4; el riesgo es menor, pero se recomienda sustituirlas
- Rust compilado a wasm: el azar venía de un generador congruencial lineal con la hora como semilla

### Diferencias con otras implementaciones

GB/T 32918.4 exige rechazar al descifrar los textos cifrados cuya salida KDF sea toda ceros. Esta biblioteca lo cumple; OpenSSL 3.0 y BouncyCastle 1.86 no lo comprueban. Con un texto claro de 1 byte ocurre aproximadamente 1 vez de cada 256.

## Rendimiento

### Apple M2: antes de la optimización, alta seguridad y alto rendimiento

Medido el 2026-11-06 en un Mac Apple M2 sin carga (macOS 14.1.1). Cada implementación se ejecutó 3 veces completas; en cada ejecución se toma la mediana de 7 muestras por operación, y las tablas muestran la mediana de las 3 ejecuciones. La mediana de la variación entre ejecuciones está entre el 0 % y el 3,7 %. Las tablas completas por algoritmo, el método, los datos en bruto y los scripts para reproducirlo están en [`compare/apple-m2/`](compare/apple-m2/README.md) (en chino).

Versión de alto rendimiento (`main`) comparada con OpenSSL 3.6.5 y BouncyCastle 1.86:

| Operación | OpenSSL 3.6.5 | BouncyCastle 1.86 | C | Rust | Go | C# | Java | JavaScript | Python | Swift |
|---|---|---|---|---|---|---|---|---|---|---|
| SM3 1 MiB (MB/s) | 354 | 245 | 310 | 388 | 323 | 371 | 246 | 352 | 0.908 | 373 |
| Cifrado SM4-CBC 1 MiB (MB/s) | 122 | 69.1 | 136 | 155 | 126 | 107 | 113 | 100 | 2.6 | 139 |
| Descifrado SM4-CBC 1 MiB (MB/s) | 141 | 71.1 | 373 | 839 | 396 | 175 | 141 | 85.9 | 8.2 | 37.7 |
| Expansión de clave SM4 (µs) | 0.35 | 0.19 | 0.10 | 0.10 | 0.14 | 0.15 | 0.36 | 0.32 | 13.2 | 0.63 |
| Generación de claves SM2 (µs) | 30.9 | 527 | 24.9 | 14.5 | 13.2 | 24.4 | 40.1 | 70.9 | 334 | 16.2 |
| Firma SM2 (µs) | 55.0 | 603 | 50.0 | 31.6 | 32.7 | 49.9 | 79.9 | 210 | 496 | 39.2 |
| Verificación SM2 (µs) | 115 | 850 | 76.0 | 76.6 | 55.9 | 123 | 227 | 242 | 709 | 55.4 |
| Cifrado SM2 32 B (µs) | 113 | 2560 | 100 | 88.0 | 69.0 | 171 | 257 | 342 | 1800 | 76.1 |
| Descifrado SM2 32 B (µs) | 77.6 | 1991 | 84.1 | 72.6 | 59.0 | 148 | 220 | 271 | 1628 | 61.1 |
| Intercambio de claves SM2 (µs) | — | 11536 | 299 | 262 | 206 | 471 | 897 | 1019 | 6935 | 233 |

Las dos ramas solo se diferencian en SM4. Cada celda indica: antes / `security` (alta seguridad) / `main` (alto rendimiento):

| Lenguaje | Cifrado 1 MiB (MB/s) | Descifrado 1 MiB (MB/s) | Expansión de clave (µs) |
|---|---|---|---|
| C | 72.7 / 60.4 / **136** | 80.0 / 195 / **373** | 0.14 / 0.34 / **0.10** |
| Rust | 22.7 / 58.3 / **155** | 67.4 / 839 / **839** | 0.17 / 0.23 / **0.10** |
| Go | 58.2 / 25.1 / **126** | 59.3 / 113 / **396** | 0.22 / 0.64 / **0.14** |
| C# | 52.3 / 24.1 / **107** | 42.0 / 23.4 / **175** | 0.23 / 0.65 / **0.15** |
| Java | 36.8 / 24.1 / **113** | 40.4 / 23.1 / **141** | 0.58 / 0.97 / **0.36** |
| JavaScript | 12.2 / 20.1 / **100** | 17.6 / 43.9 / **85.9** | 1.29 / 0.84 / **0.32** |
| Python | 0.387 / 0.102 / **2.6** | 0.387 / 8.2 / **8.2** | 32.6 / 147 / **13.2** |
| Swift | 5.3 / 20.1 / **139** | 5.1 / 20.9 / **37.7** | 3.90 / 1.08 / **0.63** |

Aceleración de `main` respecto al código anterior (más de 1 significa más rápido):

| Operación | C | Rust | Go | C# | Java | JavaScript | Python | Swift |
|---|---|---|---|---|---|---|---|---|
| SM3 1 MiB | **1.6×** | **2.9×** | **2.2×** | **2.2×** | **1.3×** | **4.3×** | **2.0×** | **3.3×** |
| Cifrado SM4-CBC 1 MiB | **1.9×** | **6.8×** | **2.2×** | **2.0×** | **3.1×** | **8.2×** | **6.7×** | **26.2×** |
| Descifrado SM4-CBC 1 MiB | **4.7×** | **12.4×** | **6.7×** | **4.2×** | **3.5×** | **4.9×** | **21.1×** | **7.3×** |
| Expansión de clave SM4 | **1.5×** | **1.7×** | **1.6×** | **1.6×** | **1.6×** | **4.1×** | **2.5×** | **6.2×** |
| Generación de claves SM2 | **8.1×** | **8.6×** | **48.4×** | **42.0×** | **459.0×** | **304.7×** | **4.8×** | **70.6×** |
| Firma SM2 | **24.2×** | **34.4×** | **96.8×** | **86.1×** | **64.0×** | **228.5×** | **8.4×** | **79.4×** |
| Verificación SM2 | **3.5×** | **3.1×** | **24.1×** | **17.7×** | **21.1×** | **179.1×** | **5.9×** | **23.5×** |
| Cifrado SM2 32 B | **3.4×** | **2.8×** | **18.6×** | **12.1×** | **18.8×** | **126.3×** | **2.1×** | **29.7×** |
| Descifrado SM2 32 B | **1.4×** | **1.5×** | **11.1×** | **6.7×** | **11.0×** | **79.8×** | **1.3×** | **17.5×** |
| Intercambio de claves SM2 | **2.9×** | **2.6×** | **16.6×** | **11.7×** | **63.4×** | **127.9×** | **2.1×** | **35.7×** |

- **Alto rendimiento (`main`):** todos los lenguajes, operaciones y tamaños son más rápidos que antes; nada empeoró. En cifrado SM4 de 1 MiB, Rust, Swift, C y Go superan a OpenSSL 3.6.5, y Java, C# y JavaScript se le acercan; en descifrado de 1 MiB, Rust, Go, C y C# superan a OpenSSL y Java lo iguala.
- **Alta seguridad (`security`):** SM4 no accede a tablas con índices que dependan de datos secretos. Go, C#, Java y Python no disponen de instrucciones de hardware en ARM y calculan la S-box como circuito booleano, por lo que su SM4 es más lento que antes (el cifrado va al 26 %–66 % de la velocidad anterior). C y Rust usan las instrucciones AES de ARM y siguen descifrando rápido.
- **SM2 y SM3 (idénticos en ambas ramas):** todos los lenguajes son mucho más rápidos. Rust, Go y Swift firman entre 1,4 y 1,7 veces más rápido que OpenSSL 3.6.5; Java es entre 7,5 veces (firma) y 13 veces (intercambio de claves) más rápido que BouncyCastle. OpenSSL no ofrece intercambio de claves SM2.
- El SM4 de OpenSSL 3.6.5 en el M2 también usa tablas: su código fuente solo usa ensamblador si la CPU tiene la extensión SM4 o es Neoverse N1/V1 o Kunpeng 920.

### x86: comparación con OpenSSL y BouncyCastle

Comparación con OpenSSL 3.0.13 y BouncyCastle 1.86 en un núcleo de alto rendimiento de un Intel i5-13500H (extracto; los resultados completos y cómo reproducirlos están en [`compare/`](compare/README.md)). Estos datos se tomaron antes de pasar SM4 a tablas, así que las cifras de SM4 corresponden a la rama `security`:

| Operación | OpenSSL | BouncyCastle | C | Rust | Go | Java |
|---|---|---|---|---|---|---|
| Firma SM2 (µs) | 202 | 311 | 37.6 | 27.5 | 31.7 | 77.1 |
| Verificación SM2 (µs) | 192 | 367 | 67.2 | 64.8 | 49.0 | 221 |
| SM3 1 MiB (MB/s) | 471 | 288 | 543 | 543 | 440 | 284 |
| Cifrado SM4 1 MiB (MB/s) | 157 | 101 | 117 | 123 | 109 | 26.4 |
| Descifrado SM4 1 MiB (MB/s) | 177 | 103 | 815 | 1298 | 519 | 24.6 |

El cifrado SM4 de la rama `security` es más lento que en OpenSSL porque no usa tablas indexadas por datos secretos.

## Demo interlenguajes

El demo verifica que las implementaciones SM2 en los ocho lenguajes pueden completar el **protocolo de intercambio de claves** y utilizar las claves negociadas para la **comunicación de cifrado/descifrado SM4**.

### Arquitectura

```
┌─────────────┐     HTTP      ┌─────────────┐
│ JS Client   │─────────────>│             │
├─────────────┤              │             │
│ Rust Client │─────────────>│   Java      │
├─────────────┤              │   Server    │
│Swift Client │─────────────>│   (B侧)     │
├─────────────┤              │             │
│ Go Client   │─────────────>│             │
├─────────────┤              │             │
│  C Client   │─────────────>│             │
├─────────────┤              │             │
│  C# Client  │─────────────>│             │
├─────────────┤              │             │
│Python Client│─────────────>│             │
└─────────────┘              └─────────────┘
     (A侧)
```

### Flujo de intercambio de claves

```
Client(A)                          Server(B)
   │                                   │
   │ 生成 dA/pA, ra/Ra                  │
   │ POST /api/keyswap/init            │
   ├──────────────────────────────────>│
   │                                   │ 生成 rb/Rb, 计算 Sb, Kb
   │        {sessionId, pB, Rb, Sb}    │
   │<──────────────────────────────────┤
   │                                   │
   │ 计算 Sa, Ka, 验证 Sb               │
   │ POST /api/keyswap/confirm {Sa}    │
   ├──────────────────────────────────>│
   │                                   │ 验证 Sa
   │                       {success}   │
   │<──────────────────────────────────┤
   │                                   │
   │ ========= Ka == Kb 密钥协商完成 =========│
   │                                   │
   │ SM4(Ka) 加密消息                    │
   │ POST /api/crypto/test             │
   ├──────────────────────────────────>│
   │                                   │ SM4(Kb) 解密验证 + 加密回复
   │     {decryptMatch, ciphertext}    │
   │<──────────────────────────────────┤
   │ SM4(Ka) 解密回复                    │
```

### Prueba rápida

```bash
cd demo
./run-tests.sh
```

## Descripción de los algoritmos

### SM2 Algoritmo criptográfico de clave pública basado en curvas elípticas

Basado en el problema del logaritmo discreto en grupos de puntos de curvas elípticas, su nivel de seguridad de 256 bits es equivalente a RSA de 2048 bits. Incluye tres componentes principales:
- **SM2-1** Algoritmo de firma digital basado en curvas elípticas
- **SM2-2** Protocolo de intercambio de claves basado en curvas elípticas
- **SM2-3** Algoritmo de cifrado de clave pública basado en curvas elípticas

### SM3 Algoritmo de hash

Genera un valor hash de 256 bits, con un nivel de seguridad significativamente superior al de MD5 (128 bits) y SHA-1 (160 bits). Es adecuado para firmas digitales, códigos de autenticación de mensajes (MAC), generación de números aleatorios y otros escenarios.

### SM4 Algoritmo de cifrado por bloques

Tanto la longitud de la clave como la del bloque son de 128 bits, coincidiendo con los parámetros de AES, y constituye el algoritmo central de cifrado simétrico en el sistema criptográfico nacional. Esta implementación utiliza el modo CBC con relleno PKCS7.

## Documentación de referencia

El directorio `doc/` contiene los documentos de especificación algorítmica publicados por la Administración Estatal de Criptografía:

| Documento | Descripción |
|------|------|
| `sm2.pdf` | Especificación del algoritmo criptográfico de clave pública SM2 basado en curvas elípticas |
| `sm2_param.pdf` | Parámetros recomendados de curvas para SM2 |
| `sm3.pdf` | Especificación del algoritmo de hash SM3 |
| `SM4.pdf` | Especificación del algoritmo de cifrado por bloques SM4 |
| `SM9.pdf` | Especificación del algoritmo criptográfico de identidad SM9 |

## Licencia

[Apache License 2.0](LICENSE)
