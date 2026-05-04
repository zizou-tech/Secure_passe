<?php

class AES256Encryption {
    private $cipher = 'aes-256-gcm';
    private $keyLength = 32; // 256 bits
    private $ivLength = 16;  // 128 bits
    private $tagLength = 16; // 128 bits
    
    /**
     * Génère une clé de chiffrement à partir d'un mot de passe
     */
    public function generateKey($password, $salt = null) {
        if ($salt === null) {
            $salt = random_bytes(16);
        }
        
        // Utilisation de PBKDF2 pour dériver la clé
        $key = hash_pbkdf2('sha256', $password, $salt, 10000, $this->keyLength, true);
        
        return [
            'key' => $key,
            'salt' => $salt
        ];
    }
    
    /**
     * Chiffre les données avec AES-256-GCM
     */
    public function encrypt($plaintext, $password) {
        try {
            // Générer le sel et la clé
            $keyData = $this->generateKey($password);
            $key = $keyData['key'];
            $salt = $keyData['salt'];
            
            // Générer un IV aléatoire
            $iv = random_bytes($this->ivLength);
            
            // Chiffrement avec authentification
            $ciphertext = openssl_encrypt(
                $plaintext,
                $this->cipher,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );
            
            if ($ciphertext === false) {
                throw new Exception('Erreur de chiffrement');
            }
            
            // Combiner toutes les données nécessaires
            $encrypted = $salt . $iv . $tag . $ciphertext;
            
            // Encoder en base64 pour le stockage
            return base64_encode($encrypted);
            
        } catch (Exception $e) {
            error_log("Erreur de chiffrement: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Déchiffre les données
     */
    public function decrypt($encryptedData, $password) {
        try {
            // Décoder de base64
            $data = base64_decode($encryptedData);
            
            if ($data === false) {
                throw new Exception('Données corrompues');
            }
            
            // Extraire les composants
            $salt = substr($data, 0, 16);
            $iv = substr($data, 16, $this->ivLength);
            $tag = substr($data, 32, $this->tagLength);
            $ciphertext = substr($data, 48);
            
            // Régénérer la clé avec le sel
            $keyData = $this->generateKey($password, $salt);
            $key = $keyData['key'];
            
            // Déchiffrement avec vérification d'authenticité
            $plaintext = openssl_decrypt(
                $ciphertext,
                $this->cipher,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );
            
            if ($plaintext === false) {
                throw new Exception('Déchiffrement échoué - mot de passe incorrect ou données corrompues');
            }
            
            return $plaintext;
            
        } catch (Exception $e) {
            error_log("Erreur de déchiffrement: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Génère un mot de passe sécurisé
     */
    public function generateSecurePassword($length = 16, $includeSymbols = true) {
        $lowercase = 'abcdefghijklmnopqrstuvwxyz';
        $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $numbers = '0123456789';
        $symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        $chars = $lowercase . $uppercase . $numbers;
        
        if ($includeSymbols) {
            $chars .= $symbols;
        }
        
        $password = '';
        $charLength = strlen($chars);
        
        // Assurer au moins un caractère de chaque type
        $password .= $lowercase[random_int(0, strlen($lowercase) - 1)];
        $password .= $uppercase[random_int(0, strlen($uppercase) - 1)];
        $password .= $numbers[random_int(0, strlen($numbers) - 1)];
        
        if ($includeSymbols) {
            $password .= $symbols[random_int(0, strlen($symbols) - 1)];
        }
        
        // Compléter avec des caractères aléatoires
        for ($i = strlen($password); $i < $length; $i++) {
            $password .= $chars[random_int(0, $charLength - 1)];
        }
        
        // Mélanger les caractères
        return str_shuffle($password);
    }
    
    /**
     * Évalue la force d'un mot de passe
     */
    public function evaluatePasswordStrength($password) {
        $score = 0;
        $feedback = [];
        
        // Longueur
        if (strlen($password) >= 12) {
            $score += 2;
        } elseif (strlen($password) >= 8) {
            $score += 1;
            $feedback[] = 'Mot de passe trop court (recommandé: 12+ caractères)';
        } else {
            $feedback[] = 'Mot de passe beaucoup trop court';
        }
        
        // Complexité
        if (preg_match('/[a-z]/', $password)) $score += 1;
        else $feedback[] = 'Ajouter des minuscules';
        
        if (preg_match('/[A-Z]/', $password)) $score += 1;
        else $feedback[] = 'Ajouter des majuscules';
        
        if (preg_match('/[0-9]/', $password)) $score += 1;
        else $feedback[] = 'Ajouter des chiffres';
        
        if (preg_match('/[^a-zA-Z0-9]/', $password)) $score += 1;
        else $feedback[] = 'Ajouter des caractères spéciaux';
        
        // Patterns communs (faiblesse)
        if (preg_match('/(.)\1{2,}/', $password)) {
            $score -= 1;
            $feedback[] = 'Éviter les caractères répétitifs';
        }
        
        if (preg_match('/123|abc|qwe|password/i', $password)) {
            $score -= 2;
            $feedback[] = 'Éviter les séquences communes';
        }
        
        // Évaluation finale
        $strength = 'Très faible';
        if ($score >= 6) $strength = 'Très fort';
        elseif ($score >= 5) $strength = 'Fort';
        elseif ($score >= 3) $strength = 'Moyen';
        elseif ($score >= 2) $strength = 'Faible';
        
        return [
            'score' => max(0, $score),
            'strength' => $strength,
            'feedback' => $feedback
        ];
    }
    
    /**
     * Hash sécurisé pour les mots de passe d'authentification
     */
    public function hashPassword($password) {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, // 64 MB
            'time_cost' => 4,       // 4 iterations
            'threads' => 3          // 3 threads
        ]);
    }
    
    /**
     * Vérifie un mot de passe hashé
     */
    public function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
}

// Classe utilitaire pour la gestion des mots de passe
class PasswordManager {
    private $encryption;
    private $pdo;
    
    public function __construct($database) {
        $this->encryption = new AES256Encryption();
        $this->pdo = $database;
    }
    
    /**
     * Sauvegarde un mot de passe chiffré
     */
    public function savePassword($userId, $siteName, $username, $password, $masterPassword, $notes = '') {
        try {
            // Chiffrer le mot de passe avec le mot de passe maître
            $encryptedPassword = $this->encryption->encrypt($password, $masterPassword);
            
            if ($encryptedPassword === false) {
                throw new Exception('Erreur de chiffrement');
            }
            
            // Évaluer la force du mot de passe
            $strength = $this->encryption->evaluatePasswordStrength($password);
            
            $stmt = $this->pdo->prepare("
                INSERT INTO saved_passwords (user_id, site_name, username, password_encrypted, notes, strength_score, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, NOW())
            ");
            
            return $stmt->execute([
                $userId, 
                $siteName, 
                $username, 
                $encryptedPassword, 
                $notes, 
                $strength['score']
            ]);
            
        } catch (Exception $e) {
            error_log("Erreur sauvegarde mot de passe: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Récupère et déchiffre un mot de passe
     */
    public function getPassword($passwordId, $userId, $masterPassword) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT * FROM saved_passwords 
                WHERE id = ? AND user_id = ?
            ");
            $stmt->execute([$passwordId, $userId]);
            $row = $stmt->fetch();
            
            if (!$row) {
                return false;
            }
            
            // Déchiffrer le mot de passe
            $decryptedPassword = $this->encryption->decrypt($row['password_encrypted'], $masterPassword);
            
            if ($decryptedPassword === false) {
                return false;
            }
            
            $row['password_decrypted'] = $decryptedPassword;
            return $row;
            
        } catch (Exception $e) {
            error_log("Erreur récupération mot de passe: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Liste tous les mots de passe d'un utilisateur (sans les déchiffrer)
     */
    public function listPasswords($userId) {
        $stmt = $this->pdo->prepare("
            SELECT id, site_name, username, notes, strength_score, created_at, updated_at
            FROM saved_passwords 
            WHERE user_id = ? 
            ORDER BY site_name ASC
        ");
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }
    
    /**
     * Génère un nouveau mot de passe sécurisé
     */
    public function generatePassword($length = 16, $includeSymbols = true) {
        return $this->encryption->generateSecurePassword($length, $includeSymbols);
    }
    
    /**
     * Évalue la force d'un mot de passe
     */
    public function checkStrength($password) {
        return $this->encryption->evaluatePasswordStrength($password);
    }
}
?>
