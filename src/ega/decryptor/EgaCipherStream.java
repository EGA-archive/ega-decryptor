/*
 * Copyright 2016 ELIXIR EGA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This is the stream cipher used to encrypt or decrypt entire files at once.
 * This class does not provide random-access capabilities.
 */

package ega.decryptor;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author asenf
 */
public class EgaCipherStream extends Thread {
    private CipherOutputStream outcipher;   // Write decrypted Data
    private BufferedInputStream instream;   // Read raw data
    private CipherInputStream incipher;     // Read encrypted data
    private BufferedOutputStream outstream; // Write raw data
    private int blocksize, pw_strength;
    private boolean mod;                    // true = encrypt, false = decrypt

    public EgaCipherStream(InputStream in, OutputStream out, int blocksize, char[] password, boolean mod) {
        this(in, out, blocksize, password, mod, 128); // Default password strength = 128
    }

    public EgaCipherStream(InputStream in, OutputStream out, int blocksize, char[] password, boolean mod, int pw_strength) {
        this.blocksize = blocksize;
        this.mod = mod;
        this.pw_strength = pw_strength;

        try {
            // File Stream Setup
            if (mod) { // encrypt -- cipher in stream (need to write iv in plain text)
                this.outstream = new BufferedOutputStream(out);
            } else { // decrypt -- cipher out stream (need to read iv in plain text)
                this.instream = new BufferedInputStream(in);
            }

            // Key Generation
            SecretKey secret = getKey(password, this.pw_strength);

            // Initialization Vector
            byte[] random_iv = new byte[16];
            if (mod) { // encrypt -- randomly generate
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                random.nextBytes(random_iv);
                try {
                    this.outstream.write(random_iv, 0, 16);
                } catch (IOException ex) {
                    Logger.getLogger(EgaCipherStream.class.getName()).log(Level.SEVERE, null, ex);
                }
            } else { // decrypt -- read from file
                try {
                    this.instream.read(random_iv, 0, 16);
                } catch (IOException ex) {
                    Logger.getLogger(EgaCipherStream.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(random_iv);

            // Cipher Setup
            Cipher cipher = null;
            cipher = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
            if (mod) {
                cipher.init(Cipher.ENCRYPT_MODE, secret, paramSpec);
                this.incipher = new CipherInputStream(in, cipher);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, secret, paramSpec);
                this.outcipher = new CipherOutputStream(out, cipher);
            }

        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException ex) {
            Logger.getLogger(EgaCipherStream.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void run() {
        if (mod)
            encrypt(); // incipher outstream
        else
            decrypt(); // instream outcipher
    }

    // Read cipher file, write raw --> encryption
    private void encrypt() {
        try {
            byte[] block = new byte[this.blocksize * 16];
            int numchars = this.incipher.read(block);
            while (numchars != -1) {
                if (numchars < (this.blocksize * 16)) {
                    block = new_fill(block, numchars);
                }
                this.outstream.write(block, 0, numchars);
                numchars = this.incipher.read(block);
            }
            this.outstream.close();
            this.incipher.close();
        } catch (IOException ex) {
            Logger.getLogger(EgaCipherStream.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    // Read raw, write cipher file --> decryption
    private void decrypt() {
        try {
            byte[] block = new byte[this.blocksize * 16];
            int numchars = this.instream.read(block);
            while (numchars != -1) {
                if (numchars < (this.blocksize * 16)) {
                    block = new_fill(block, numchars);
                }
                this.outcipher.write(block, 0, numchars);
                numchars = this.instream.read(block);
            }
            this.outcipher.flush();
            this.outcipher.close();
            this.outstream.close();
            this.instream.close();
        } catch (IOException ex) {
            Logger.getLogger(EgaCipherStream.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    // Used on the last block ... overwrite data at end with -1
    private static byte[] new_fill(byte[] in, int numchars) {
        int nb = 16 * (numchars / 16) + 16;
        byte[] result = new byte[nb];
        System.arraycopy(in, 0, result, 0, numchars);
        for (int i = numchars; i < nb; i++) {
            result[i] = -1;
        }
        return result;
    }

    // Get a cipher object, based on provided initialization objects - iv returned through parameters
    public static Cipher getCipher(char[] password, boolean mod, int pw_strength, byte[] iv) {
        Cipher cipher = null;

        try {
            // Key Generation
            SecretKey secret = getKey(password, pw_strength);

            // Initialization Vector
            byte[] random_iv = new byte[16];
            if (mod) { // encrypt -- randomly generate
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                random.nextBytes(random_iv);
                System.arraycopy(random_iv, 0, iv, 0, 16);
            } else { // decrypt -- read from file
                System.arraycopy(iv, 0, random_iv, 0, 16);
            }
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(random_iv);

            // Cipher Setup
            cipher = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
            if (mod) {
                cipher.init(Cipher.ENCRYPT_MODE, secret, paramSpec);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, secret, paramSpec);
            }

        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException ex) {
            Logger.getLogger(EgaCipherStream.class.getName()).log(Level.SEVERE, null, ex);
        }

        return cipher;
    }

    private static SecretKey getKey(char[] password, int pw_strength) {
        // Key Generation
        byte[] salt = {(byte) -12, (byte) 34, (byte) 1, (byte) 0, (byte) -98, (byte) 223, (byte) 78, (byte) 21};
        SecretKeyFactory factory;
        SecretKey secret = null;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(password, salt, 1024, pw_strength); // Password Strength - n bits
            SecretKey tmp = factory.generateSecret(spec);
            secret = new SecretKeySpec(tmp.getEncoded(), "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(EgaCipherStream.class.getName()).log(Level.SEVERE, null, ex);
        }
        return secret;
    }
}
