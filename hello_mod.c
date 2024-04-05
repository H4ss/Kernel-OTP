#include <linux/module.h>       // Nécessaire pour tous les modules
#include <linux/kernel.h>       // Nécessaire pour KERN_INFO

// Fonction appelée au chargement du module
int init_module(void) {
    printk(KERN_INFO "Bonjour le monde 1.\n");
    // Retourne 0 si tout va bien, et un autre code d'erreur sinon
    return 0;
}

// Fonction appelée à la suppression du module
void cleanup_module(void) {
    printk(KERN_INFO "Au revoir le monde 1.\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hassan ZABATT <hassan.zabatt@epitech.eu>");
MODULE_DESCRIPTION("Epitech - Kernel development module (M-KRN-900) project.");
MODULE_VERSION("1.0");