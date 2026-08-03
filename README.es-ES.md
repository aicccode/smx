

# SMX - Implementación Multilingüe de Algoritmos Criptográficos Nacionales

Basado completamente en los estándares de algoritmos criptográficos comerciales publicados por la Administración Estatal de Criptografía, esta implementación logra la aplicación integral de los algoritmos criptográficos nacionales SM2, SM3 y SM4 en siete lenguajes de programación principales: **Java, JavaScript, Swift, Rust, Go, C y C#**, con **cero dependencias de terceros**.

Todas las implementaciones siguen estrictamente las especificaciones algorítmicas y los casos de prueba publicados por la Administración Estatal de Criptografía. La salida de los algoritmos coincide completamente con los estándares de prueba oficiales, por lo que pueden aplicarse directamente al desarrollo y despliegue de productos de criptografía comercial.

## Matriz de funcionalidades

| Funcionalidad | Java | JavaScript | Swift | Rust | Go | C | C# |
|------|:----:|:----------:|:-----:|:----:|:--:|:-:|:--:|
| Hash SM3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cifrado/Descifrado Simétrico SM4 (CBC/PKCS7) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cifrado/Descifrado Asimétrico SM2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Firma Digital / Verificación SM2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Intercambio de Claves SM2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

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
├── demo/            # Demo de intercambio de claves y comunicación cifrada entre lenguajes
│   ├── server-java/     # Servidor HTTP Java (Lado B)
│   ├── client-js/       # Cliente JavaScript (Lado A)
│   ├── client-rust/     # Cliente Rust (Lado A)
│   ├── client-swift/    # Cliente Swift (Lado A)
│   ├── client-go/       # Cliente Go (Lado A)
│   ├── client-c/        # Cliente C (Lado A, libcurl)
│   ├── client-csharp/   # Cliente C# (Lado A, .NET 8)
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
- **Versión mínima:** Rust 2024 edition
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

## Demo interlenguajes

El demo verifica que las implementaciones SM2 en los siete lenguajes pueden completar el **protocolo de intercambio de claves** y utilizar las claves negociadas para la **comunicación de cifrado/descifrado SM4**.

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
