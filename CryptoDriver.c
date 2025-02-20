#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <linux/statfs.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/kobject.h>
#include <linux/path.h>
#include <linux/namei.h>

// Definiciones de constantes y macros
#define DRIVER_NAME "CryptoDriver" // Nombre del controlador
#define DRIVER_CLASS "CryptoDriverClass" // Clase del controlador
#define NUM_DEVICES 4 // Número de dispositivos lógicos manejados por el driver
#define XOR_MAX_SIZE 1024 // Tamaño máximo del buffer de cifrado XOR
#define SHA256_SIZE 32 // Tamaño del resultado de hash SHA-256

// Variables globales
static dev_t major_minor = -1; // Número mayor y menor del dispositivo
static struct cdev crypto_cdev[NUM_DEVICES]; // Estructura cdev para los dispositivos
static struct class *crypto_class = NULL; // Clase del dispositivo

// Buffers y variables para cifrado XOR y hash SHA-256
static char xor_buffer[XOR_MAX_SIZE]; // Buffer para datos cifrados con XOR
static char xor_key[XOR_MAX_SIZE]; // Clave para cifrado XOR
static bool xor_key_generated = false; // Indicador de si la clave XOR ha sido generada
static size_t xor_len = 0; // Longitud de los datos cifrados con XOR

static char hash_result[SHA256_SIZE]; // Resultado del hash SHA-256
static size_t hash_len = 0; // Longitud del hash SHA-256

// Declaraciones de funciones de operación de archivo
static int crypto_open(struct inode *inode, struct file *file);
static ssize_t crypto_read(struct file *file, char __user *buffer, size_t count, loff_t *f_pos);
static ssize_t crypto_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos);
static int crypto_release(struct inode *inode, struct file *file);

// Estructura de operaciones de archivo
static const struct file_operations crypto_fops = {
    .owner = THIS_MODULE,
    .open = crypto_open,
    .read = crypto_read,
    .write = crypto_write,
    .release = crypto_release,
};

// Función de apertura del archivo de dispositivo
static int crypto_open(struct inode *inode, struct file *file) {
    pr_info("CryptoDriver opened\n");
    return 0;
}

// Función de lectura del archivo de dispositivo
static ssize_t crypto_read(struct file *file, char __user *buffer, size_t count, loff_t *f_pos) {
    int minor = iminor(file_inode(file)); // Obtener el número menor del dispositivo

    if (minor == 0) {
        // Generación de clave XOR solo una vez
        if (!xor_key_generated) {
            get_random_bytes(xor_key, XOR_MAX_SIZE);  // Generar la clave XOR
            xor_key_generated = true; // Marcar que la clave ha sido generada
            pr_info("XOR key generated: ");
            for (size_t i = 0; i < XOR_MAX_SIZE; i++) {
    		pr_cont("%02x", xor_key[i]); // Imprimir la clave generada
	    }
	    pr_cont("\n");

            // Enviar la clave al espacio de usuario
            if (copy_to_user(buffer, xor_key, XOR_MAX_SIZE)) {
                return -EFAULT; // Error al copiar la clave al espacio de usuario
            }
            return XOR_MAX_SIZE;  // Devolver el tamaño de la clave
        }
        return 0;  // Si ya se generó la clave, no hacer nada
    } else if (minor == 1) {
        // Encriptación - Escribir en CryptoDriver1
        if (xor_len == 0) {
            pr_info("XOR buffer is empty, nothing to read\n");
            return 0;
        }

        // Evitar lectura repetida
        if (*f_pos >= xor_len) {
            pr_info("End of XOR data reached\n");
            return 0;
        }

        size_t to_copy = min(count, xor_len - *f_pos); // Calcular la cantidad de datos a copiar
        if (copy_to_user(buffer, xor_buffer + *f_pos, to_copy)) {
            pr_err("Failed to copy XOR data to user space\n");
            return -EFAULT;
        }

        *f_pos += to_copy; // Actualiza f_pos después de la lectura
        pr_info("XOR data read, length: %zu\n", to_copy);
        return to_copy; // Devolver la cantidad de datos leídos
    } else if (minor == 2) {
        if (xor_len == 0) {
            pr_info("XOR buffer is empty, nothing to read\n");
            return 0;
        }

        // Verificar si la clave XOR ya fue generada
        if (!xor_key_generated) {
            pr_err("XOR key not generated yet\n");
            return -EINVAL;
        }

	// Imprimir la clave utilizada para descifrar
    	pr_info("Using XOR key for decryption: ");
    	for (size_t i = 0; i < xor_len; i++) {
       		pr_cont("%02x", xor_key[i]);
    	}
    	pr_cont("\n");	
	
        // Desencriptar los datos (aplicando XOR con la misma clave)
        size_t to_copy = min(count, xor_len - *f_pos); // Calcular la cantidad de datos a copiar
        char *decrypted_data = kmalloc(to_copy, GFP_KERNEL); // Reservar memoria para los datos desencriptados
        if (!decrypted_data)
            return -ENOMEM; // Error de memoria insuficiente

        // Desencriptar los datos
        for (size_t i = 0; i < to_copy; i++) {
            decrypted_data[i] = xor_buffer[*f_pos + i] ^ xor_key[*f_pos + i];  // Desencriptación
        }

        if (copy_to_user(buffer, decrypted_data, to_copy)) {
            kfree(decrypted_data); // Liberar memoria en caso de error
            return -EFAULT; // Error al copiar datos al espacio de usuario
        }

        *f_pos += to_copy;  // Actualiza f_pos después de la lectura
        pr_info("Decrypted data read, length: %zu\n", to_copy);

        kfree(decrypted_data); // Liberar memoria después de usarla
        return to_copy; // Devolver la cantidad de datos leídos
    } else if (minor == 3) {  // SHA-256 Hash
        if (*f_pos >= hash_len) return 0; // Fin de los datos de hash alcanzado

        size_t to_copy = min(count, hash_len - *f_pos); // Calcular la cantidad de datos a copiar
        if (copy_to_user(buffer, hash_result + *f_pos, to_copy)) return -EFAULT; // Error al copiar datos al espacio de usuario
        *f_pos += to_copy; // Actualizar f_pos después de la lectura
        return to_copy; // Devolver la cantidad de datos leídos
    }

    return 0; // Devolver 0 si no se cumple ninguna condición previa
}

// Función de escritura del archivo de dispositivo
static ssize_t crypto_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos) {
    int minor = iminor(file_inode(file)); // Obtener el número menor del dispositivo

    if (minor == 1) {
        if (count > XOR_MAX_SIZE) {
            pr_err("Attempt to write more than max XOR size\n");
            return -EINVAL; // Error, intento de escribir más del tamaño máximo permitido
        }
        if (copy_from_user(xor_buffer, buffer, count)) {
            pr_err("Failed to copy data from user space to kernel\n");
            return -EFAULT; // Error al copiar datos del espacio de usuario al kernel
        }

        // Verificar si la clave XOR ya fue generada
        if (!xor_key_generated) {
            pr_err("XOR key not generated yet\n");
            return -EINVAL;
        }
        
        // Imprimir la clave utilizada para cifrar
    	pr_info("Using XOR key for encryption: ");
    	for (size_t i = 0; i < count; i++) {
        	pr_cont("%02x", xor_key[i]);
    	}
    	pr_cont("\n");

        // Encriptar los datos usando la clave XOR generada
        for (size_t i = 0; i < count; i++) {
            xor_buffer[i] ^= xor_key[i];
        }

        xor_len = count; // Actualizar la longitud de los datos cifrados
        pr_info("XOR data written and encrypted, length: %zu\n", xor_len);
        return count; // Devolver la cantidad de datos escritos
    }else if (minor == 3) {  // SHA-256 Hash
        struct shash_desc *desc;
        struct crypto_shash *tfm;
        char *data;
        struct kstatfs stat;

        tfm = crypto_alloc_shash("sha256", 0, 0); // Crear la transformación de hash SHA-256
        if (IS_ERR(tfm)) return PTR_ERR(tfm); // Error al crear la transformación

        desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL); // Reservar memoria para la descripción del hash
        if (!desc) {
            crypto_free_shash(tfm); // Liberar la transformación en caso de error
            return -ENOMEM; // Error de memoria insuficiente
        }

        desc->tfm = tfm; // Asignar la transformación a la descripción

        data = kmalloc(count, GFP_KERNEL); // Reservar memoria para los datos
        if (!data) {
            kfree(desc); // Liberar la descripción en caso de error
            crypto_free_shash(tfm); // Liberar la transformación en caso de error
            return -ENOMEM; // Error de memoria insuficiente
        }

        if (copy_from_user(data, buffer, count)) {
            kfree(data); // Liberar datos en caso de error
            kfree(desc); // Liberar la descripción en caso de error
            crypto_free_shash(tfm); // Liberar la transformación en caso de error
            return -EFAULT; // Error al copiar datos del espacio de usuario al kernel
        }

        crypto_shash_init(desc); // Inicializar la descripción del hash
        crypto_shash_update(desc, data, count); // Actualizar el hash con los datos
        crypto_shash_final(desc, hash_result); // Finalizar el cálculo del hash

        hash_len = SHA256_SIZE; // Actualizar la longitud del hash
        
        struct path root_path;

        if (kern_path("/", LOOKUP_FOLLOW, &root_path) == 0) {
            if (vfs_statfs(&root_path, &stat) == 0) {
                pr_info("Espacio libre en disco: %llu KB\n", stat.f_bfree * (stat.f_bsize / 1024));
            } else {
                pr_err("Error al obtener el estado del sistema de archivos\n");
            }
            path_put(&root_path);
        } else {
            pr_err("Error al obtener el path de la raíz\n");
        }
        
        kfree(data); // Liberar datos después de usarlos
        kfree(desc); // Liberar la descripción después de usarla
        crypto_free_shash(tfm); // Liberar la transformación después de usarla

        pr_info("SHA-256 hash calculated successfully\n");
        return count; // Devolver la cantidad de datos escritos
    }

    return -EINVAL; // Devolver error si no se cumple ninguna condición previa
}



// Función de liberación del archivo de dispositivo
static int crypto_release(struct inode *inode, struct file *file) {
    pr_info("CryptoDriver released\n");
    return 0;
}

// Función de inicialización del módulo
static int __init crypto_init(void) {
    int i;
    dev_t dev_id;

    if (alloc_chrdev_region(&major_minor, 0, NUM_DEVICES, DRIVER_NAME) < 0) {
        pr_err("Failed to allocate major number\n");
        return -1; // Error al asignar el número mayor
    }

    crypto_class = class_create(DRIVER_CLASS); // Crear la clase del dispositivo
    if (IS_ERR(crypto_class)) {
        unregister_chrdev_region(major_minor, NUM_DEVICES); // Desregistrar el número mayor en caso de error
        pr_err("Failed to create class\n");
        return PTR_ERR(crypto_class);
    }

    for (i = 0; i < NUM_DEVICES; i++) {
        cdev_init(&crypto_cdev[i], &crypto_fops); // Inicializar la estructura cdev
        dev_id = MKDEV(MAJOR(major_minor), MINOR(major_minor) + i); // Crear el identificador del dispositivo
        if (cdev_add(&crypto_cdev[i], dev_id, 1)) {
            pr_err("Failed to add cdev %d\n", i); // Error al añadir el cdev
        }
        if (IS_ERR(device_create(crypto_class, NULL, dev_id, NULL, DRIVER_NAME "%d", i))) {
            pr_err("Failed to create device %d\n", i); // Error al crear el dispositivo
        }
    }

    pr_info("CryptoDriver initialized\n");
    return 0; // Devolver 0 si la inicialización fue exitosa
}

// Función de limpieza del módulo
static void __exit crypto_exit(void) {
    int i;
    for (i = 0; i < NUM_DEVICES; i++) {
        device_destroy(crypto_class, MKDEV(MAJOR(major_minor), MINOR(major_minor) + i));
        cdev_del(&crypto_cdev[i]); // Eliminar el cdev
    }
    class_destroy(crypto_class); // Destruir la clase del dispositivo
    unregister_chrdev_region(major_minor, NUM_DEVICES); // Desregistrar el número mayor
    pr_info("CryptoDriver unloaded\n");
}

// Macros para registrar las funciones de inicialización y limpieza del módulo
MODULE_LICENSE("GPL");
module_init(crypto_init);
module_exit(crypto_exit);

