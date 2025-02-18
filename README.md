# CryptoDriver - Driver de Kernel para Operaciones Criptográficas

## Descripción General
CryptoDriver es un módulo de kernel de Linux que implementa cuatro dispositivos lógicos para realizar operaciones criptográficas básicas:

1. **Generación de clave XOR**: Genera una clave XOR aleatoria de hasta 1024 bytes.
2. **Cifrado XOR**: Cifra datos mediante XOR usando la clave generada.
3. **Descifrado XOR**: Descifra datos cifrados con la clave XOR.
4. **Cálculo de Hash SHA-256**: Calcula el hash SHA-256 de los datos proporcionados y muestra información sobre el espacio libre en disco.

---

## Instalación

Para compilar e instalar el driver:

```bash
make
```
```bash
sudo insmod CryptoDriver.ko
```

Para darle permisos a los dispositivos:

```bash
sudo chmod 766 /dev/CryptoDriver0
sudo chmod 766 /dev/CryptoDriver1
sudo chmod 766 /dev/CryptoDriver2
sudo chmod 766 /dev/CryptoDriver3
```

Para verificar la instalación:

```bash
cat /proc/devices | grep CryptoDriver
tree /sys/devices/virtual/CryptoDriverClass/
ls -l /dev/CryptoDriver*
```

---

## Uso

Cada dispositivo se accede a través de `/dev/CryptoDriver0`, `/dev/CryptoDriver1`, etc. Se pueden usar comandos `echo`, `cat`, o programas en C para interactuar.

**Ejemplos:**

- Generar clave XOR:
  ```bash
  cat /dev/CryptoDriver0 | xxd -p
  ```

- Cifrar datos:
  ```bash
  echo "mensaje" > /dev/CryptoDriver1
  cat /dev/CryptoDriver1 | xxd -p
  ```

- Descifrar datos:
  ```bash
  cat /dev/CryptoDriver2
  ```

- Calcular hash SHA-256:
  ```bash
  echo "texto" > /dev/CryptoDriver3
  cat /dev/CryptoDriver3 | xxd -p
  ```
  
- Comprobar que el hash coincide realmente:
  ```bash
  echo "texto" | sha256sum
  ```

- Comprobar los logs:
  ```bash
  sudo dmesg | tail -n 25
  ```
  
---

## Estructura del Código

- **Manejo de dispositivos:** Implementación con `cdev` y `file_operations`.
- **Cifrado XOR:** Uso de `get_random_bytes` para la clave.
- **Hash SHA-256:** Uso de API de `crypto` del kernel.
- **Información de disco:** Obtención de espacio libre mediante `vfs_statfs`.

---

## Desinstalación

```bash
sudo rmmod CryptoDriver
```
```bash
make clean
```

---

## Autor
- **Manuel Garrido Fúnez** - Práctica de la asignatura Programación Hardware

---

## Licencia

Este proyecto está bajo la Licencia GPL v2.

