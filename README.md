# Secure Chat

Un sistema de chat seguro implementado en C que utiliza cifrado RSA para comunicaciones privadas entre clientes a través de un servidor central.

## Descripción

Secure Chat es una aplicación de chat en tiempo real que permite a múltiples usuarios conectarse a un servidor y comunicarse de forma segura. El sistema implementa cifrado RSA de extremo a extremo para mensajes privados, garantizando que solo el remitente y el destinatario puedan leer el contenido de los mensajes.

## Características

- **Chat público**: Mensajes broadcast visibles para todos los usuarios conectados
- **Mensajes privados cifrados**: Comunicación segura entre usuarios específicos usando RSA-2048
- **Autenticación de usuarios**: Sistema de nombres únicos con validación
- **Múltiples clientes**: Soporte para hasta 10 usuarios simultáneos
- **Interfaz colorizada**: Cada usuario tiene un color distintivo en el chat
- **Comandos integrados**: Sistema de comandos para gestionar la sesión

## Arquitectura del Sistema

### Componentes

1. **Servidor (`server.c`)**
   - Gestiona conexiones de múltiples clientes
   - Retransmite mensajes públicos
   - Facilita el intercambio de claves públicas
   - Maneja mensajes privados cifrados
   - Dos puertos: principal (chat) y privado (intercambio de claves)

2. **Cliente (`client.c`)**
   - Genera par de claves RSA al conectar
   - Envía/recibe mensajes en tiempo real
   - Cifra/descifra mensajes privados
   - Interfaz de línea de comandos

### Protocolo de Seguridad

- **Cifrado**: RSA-2048 con padding OAEP
- **Intercambio de claves**: Las claves públicas se intercambian a través del servidor
- **Serialización**: Los mensajes cifrados se codifican en Base64 para transmisión

## Requisitos

### Dependencias del Sistema
- **OpenSSL**: Para funcionalidades criptográficas
- **pthread**: Para manejo de hilos
- **Compilador GCC**: Compatible con C99 o superior

### Instalación de Dependencias

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libssl-dev build-essential
```

**CentOS/RHEL:**
```bash
sudo yum install openssl-devel gcc
```

**macOS:**
```bash
brew install openssl
```

## Compilación

```bash
# Compilar el servidor
gcc -o server server.c -lssl -lcrypto -lpthread

# Compilar el cliente
gcc -o client client.c -lssl -lcrypto -lpthread
```

## Uso

### Iniciar el Servidor

```bash
./server <puerto>
```

Ejemplo:
```bash
./server 8080
```

El servidor utilizará automáticamente el puerto especificado para chat general y puerto+1 para comunicación privada.

### Conectar Clientes

```bash
./client <host> <puerto>
```

Ejemplo:
```bash
./client 127.0.0.1 8080
```

### Comandos Disponibles

Una vez conectado, puedes usar los siguientes comandos:

- `/list` - Mostrar todos los usuarios conectados
- `/private <usuario> <mensaje>` - Enviar mensaje privado cifrado
- `/help` - Mostrar lista de comandos disponibles
- `/exit` - Desconectar del servidor

### Ejemplo de Sesión

```
[system] Welcome to the chat. Please enter your name: Alice
[system] Welcome to the chat Alice. Use /help to see the available commands.
[system] Connected clients: Alice (you), Bob

Hello everyone!
[broadcast] Bob<Bob> Hi Alice!

/private Bob This is a secret message
/list
--- Connected clients ---
Alice (you)
Bob

/exit
```

## Características de Seguridad

### Cifrado de Mensajes Privados

1. **Generación de claves**: Cada cliente genera un par RSA-2048 al conectar
2. **Intercambio de claves**: Las claves públicas se intercambian automáticamente
3. **Cifrado**: Los mensajes privados se cifran con la clave pública del destinatario
4. **Transmisión segura**: Los mensajes cifrados se codifican en Base64
5. **Descifrado**: Solo el destinatario puede descifrar con su clave privada

### Limitaciones de Seguridad

- Los mensajes públicos **NO** están cifrados
- El servidor puede ver metadatos (quién envía a quién)
- No hay verificación de integridad de claves públicas
- Vulnerable a ataques man-in-the-middle en el intercambio de claves

## Limitaciones del Sistema

- **Máximo 10 clientes** simultáneos
- **Nombres únicos**: No se permiten nombres duplicados
- **Sin persistencia**: Los mensajes no se guardan
- **Reconexión manual**: No hay reconexión automática
- **Buffer limitado**: Mensajes de máximo 4096 caracteres

## Estructura del Proyecto

```
Secure-Chat/
├── server.c          # Implementación del servidor
├── client.c          # Implementación del cliente
├── .gitignore        # Archivos ignorados por Git
└── README.md         # Esta documentación
```

## Solución de Problemas

### Errores Comunes

**Error de conexión:**
```
connect: Connection refused
```
- Verificar que el servidor esté ejecutándose
- Confirmar host y puerto correctos

**Error de SSL:**
```
Error generating RSA key pair
```
- Verificar instalación de OpenSSL
- Comprobar permisos del sistema

**Servidor completo:**
```
[system] Error: The server is full.
```
- Esperar a que se libere una conexión
- Máximo 10 usuarios simultáneos

## Desarrollo y Contribución

### Compilación con Debug
```bash
gcc -g -o server server.c -lssl -lcrypto -lpthread
gcc -g -o client client.c -lssl -lcrypto -lpthread
```
