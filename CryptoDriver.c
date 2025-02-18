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

#define DRIVER_NAME "CryptoDriver"
#define DRIVER_CLASS "CryptoDriverClass"
#define NUM_DEVICES 4
#define XOR_MAX_SIZE 1024
#define SHA256_SIZE 32

static dev_t major_minor = -1;
static struct cdev crypto_cdev[NUM_DEVICES];
static struct class *crypto_class = NULL;

static char xor_buffer[XOR_MAX_SIZE];
static char xor_key[XOR_MAX_SIZE];
static bool xor_key_generated = false;
static size_t xor_len = 0;

static char hash_result[SHA256_SIZE];
static size_t hash_len = 0;

static int crypto_open(struct inode *inode, struct file *file);
static ssize_t crypto_read(struct file *file, char __user *buffer, size_t count, loff_t *f_pos);
static ssize_t crypto_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos);
static int crypto_release(struct inode *inode, struct file *file);

static const struct file_operations crypto_fops = {
    .owner = THIS_MODULE,
    .open = crypto_open,
    .read = crypto_read,
    .write = crypto_write,
    .release = crypto_release,
};

static int crypto_open(struct inode *inode, struct file *file) {
    pr_info("CryptoDriver opened\n");
    return 0;
}

static ssize_t crypto_read(struct file *file, char __user *buffer, size_t count, loff_t *f_pos) {
    int minor = iminor(file_inode(file));

    if (minor == 0) {
        // Generación de clave XOR solo una vez
        if (!xor_key_generated) {
            get_random_bytes(xor_key, XOR_MAX_SIZE);  // Generar la clave
            xor_key_generated = true;
            pr_info("XOR key generated: ");
            for (size_t i = 0; i < XOR_MAX_SIZE; i++) {
    		pr_cont("%02x", xor_key[i]);
	    }
	    pr_cont("\n");

            // Enviar la clave al espacio de usuario
            if (copy_to_user(buffer, xor_key, XOR_MAX_SIZE)) {
                return -EFAULT;
            }
            return XOR_MAX_SIZE;  // Solo se envía la clave
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

        size_t to_copy = min(count, xor_len - *f_pos);
        if (copy_to_user(buffer, xor_buffer + *f_pos, to_copy)) {
            pr_err("Failed to copy XOR data to user space\n");
            return -EFAULT;
        }

        *f_pos += to_copy; // Actualiza f_pos después de la lectura
        pr_info("XOR data read, length: %zu\n", to_copy);
        return to_copy;
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
        size_t to_copy = min(count, xor_len - *f_pos);
        char *decrypted_data = kmalloc(to_copy, GFP_KERNEL);
        if (!decrypted_data)
            return -ENOMEM;

        // Desencriptar los datos
        for (size_t i = 0; i < to_copy; i++) {
            decrypted_data[i] = xor_buffer[*f_pos + i] ^ xor_key[*f_pos + i];  // Desencriptación
        }

        if (copy_to_user(buffer, decrypted_data, to_copy)) {
            kfree(decrypted_data);
            return -EFAULT;
        }

        *f_pos += to_copy;  // Actualiza f_pos después de la lectura
        pr_info("Decrypted data read, length: %zu\n", to_copy);

        kfree(decrypted_data);
        //xor_key_generated = false;
        return to_copy;
    } else if (minor == 3) {  // SHA-256 Hash
        if (*f_pos >= hash_len) return 0;

        size_t to_copy = min(count, hash_len - *f_pos);
        if (copy_to_user(buffer, hash_result + *f_pos, to_copy)) return -EFAULT;
        *f_pos += to_copy;
        return to_copy;
    }

    return 0;
}

static ssize_t crypto_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos) {
    int minor = iminor(file_inode(file));

    if (minor == 1) {
        if (count > XOR_MAX_SIZE) {
            pr_err("Attempt to write more than max XOR size\n");
            return -EINVAL;
        }
        if (copy_from_user(xor_buffer, buffer, count)) {
            pr_err("Failed to copy data from user space to kernel\n");
            return -EFAULT;
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

        xor_len = count;
        pr_info("XOR data written and encrypted, length: %zu\n", xor_len);
        return count;
    }else if (minor == 3) {  // SHA-256 Hash
        struct shash_desc *desc;
        struct crypto_shash *tfm;
        char *data;
        struct kstatfs stat;

        tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(tfm)) return PTR_ERR(tfm);

        desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
        if (!desc) {
            crypto_free_shash(tfm);
            return -ENOMEM;
        }

        desc->tfm = tfm;

        data = kmalloc(count, GFP_KERNEL);
        if (!data) {
            kfree(desc);
            crypto_free_shash(tfm);
            return -ENOMEM;
        }

        if (copy_from_user(data, buffer, count)) {
            kfree(data);
            kfree(desc);
            crypto_free_shash(tfm);
            return -EFAULT;
        }

        crypto_shash_init(desc);
        crypto_shash_update(desc, data, count);
        crypto_shash_final(desc, hash_result);

        hash_len = SHA256_SIZE;
        
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
        
        kfree(data);
        kfree(desc);
        crypto_free_shash(tfm);

        pr_info("SHA-256 hash calculated successfully\n");
        return count;
    }

    return -EINVAL;
}




static int crypto_release(struct inode *inode, struct file *file) {
    pr_info("CryptoDriver released\n");
    return 0;
}

static int __init crypto_init(void) {
    int i;
    dev_t dev_id;

    if (alloc_chrdev_region(&major_minor, 0, NUM_DEVICES, DRIVER_NAME) < 0) {
        pr_err("Failed to allocate major number\n");
        return -1;
    }

    crypto_class = class_create(DRIVER_CLASS);
    if (IS_ERR(crypto_class)) {
        unregister_chrdev_region(major_minor, NUM_DEVICES);
        pr_err("Failed to create class\n");
        return PTR_ERR(crypto_class);
    }

    for (i = 0; i < NUM_DEVICES; i++) {
        cdev_init(&crypto_cdev[i], &crypto_fops);
        dev_id = MKDEV(MAJOR(major_minor), MINOR(major_minor) + i);
        if (cdev_add(&crypto_cdev[i], dev_id, 1)) {
            pr_err("Failed to add cdev %d\n", i);
        }
        if (IS_ERR(device_create(crypto_class, NULL, dev_id, NULL, DRIVER_NAME "%d", i))) {
            pr_err("Failed to create device %d\n", i);
        }
    }

    pr_info("CryptoDriver initialized\n");
    return 0;
}

static void __exit crypto_exit(void) {
    int i;
    for (i = 0; i < NUM_DEVICES; i++) {
        device_destroy(crypto_class, MKDEV(MAJOR(major_minor), MINOR(major_minor) + i));
        cdev_del(&crypto_cdev[i]);
    }
    class_destroy(crypto_class);
    unregister_chrdev_region(major_minor, NUM_DEVICES);
    pr_info("CryptoDriver unloaded\n");
}

MODULE_LICENSE("GPL");
module_init(crypto_init);
module_exit(crypto_exit);

