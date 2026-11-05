

# SMX - Implementación Multilingüe de Algoritmos Criptográficos Nacionales

Basado completamente en los estándares de algoritmos criptográficos comerciales publicados por la Administración Estatal de Criptografía, esta implementación logra la aplicación integral de los algoritmos criptográficos nacionales SM2, SM3 y SM4 en ocho lenguajes de programación principales: **Java, JavaScript, Swift, Rust, Go, C, C# y Python**, con **cero dependencias de terceros**.

Todas las implementaciones siguen estrictamente las especificaciones algorítmicas y los casos de prueba publicados por la Administración Estatal de Criptografía. La salida de los algoritmos coincide completamente con los estándares de prueba oficiales, por lo que pueden aplicarse directamente al desarrollo y despliegue de productos de criptografía comercial.

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

- Las operaciones con la clave privada (generación de claves, firma, descifrado, intercambio de claves) usan ventanas fijas y selección enmascarada en tablas, sin ramas ni direcciones de memoria que dependan de datos secretos. C, Rust y Swift incluyen herramientas que revisan el código compilado (`make check-ct` en C, `rust/tools/check_ct_asm.py`, `swift/Tools/check_constant_time.py`); vuelva a ejecutarlas al cambiar de compilador.
- SM4 nunca usa tablas indexadas por datos secretos: utiliza AES-NI, GFNI o las instrucciones AES de ARM cuando existen y, si no, una S-box implementada como circuito booleano.
- Java, C#, JavaScript y Python se ejecutan en entornos gestionados que no garantizan tiempo constante; la biblioteca solo puede evitar en el código fuente las ramas y los accesos a tablas que dependen de secretos.
- La verificación de firmas solo maneja datos públicos y usa algoritmos de tiempo variable por velocidad.

### Claves antiguas que deben sustituirse

Las claves generadas con versiones anteriores en estos entornos usaban una fuente aleatoria insegura y **deben sustituirse**; las firmas antiguas hechas con ellas tampoco deben considerarse fiables:

- JavaScript en Node.js 18 o anterior: el azar venía por completo de `Math.random`
- JavaScript en navegadores o Node.js 20 o posterior: mezclaba `Math.random` y RC4; el riesgo es menor, pero se recomienda sustituirlas
- Rust compilado a wasm: el azar venía de un generador congruencial lineal con la hora como semilla

### Diferencias con otras implementaciones

GB/T 32918.4 exige rechazar al descifrar los textos cifrados cuya salida KDF sea toda ceros. Esta biblioteca lo cumple; OpenSSL 3.0 y BouncyCastle 1.86 no lo comprueban. Con un texto claro de 1 byte ocurre aproximadamente 1 vez de cada 256.

## Rendimiento

Comparación con OpenSSL 3.0.13 y BouncyCastle 1.86 en un núcleo de alto rendimiento de un Intel i5-13500H (extracto; los resultados completos y cómo reproducirlos están en [`compare/`](compare/README.md)):

| Operación | OpenSSL | BouncyCastle | C | Rust | Go | Java |
|---|---|---|---|---|---|---|
| Firma SM2 (µs) | 202 | 311 | 37.6 | 27.5 | 31.7 | 77.1 |
| Verificación SM2 (µs) | 192 | 367 | 67.2 | 64.8 | 49.0 | 221 |
| SM3 1 MiB (MB/s) | 471 | 288 | 543 | 543 | 440 | 284 |
| Cifrado SM4 1 MiB (MB/s) | 157 | 101 | 117 | 123 | 109 | 26.4 |
| Descifrado SM4 1 MiB (MB/s) | 177 | 103 | 815 | 1298 | 519 | 24.6 |

El cifrado SM4 es más lento que en OpenSSL porque esta biblioteca no usa tablas indexadas por datos secretos.

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
