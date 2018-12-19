package com.tectiv3.aes;

import android.widget.Toast;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import java.util.UUID;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;

import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;

import android.util.Base64;

import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;

public class RCTAes extends ReactContextBaseJavaModule {

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";
    public static final String HMAC_SHA_256 = "HmacSHA256";
    private static final String KEY_ALGORITHM = "AES";
    private static final String SECRET_KEY_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";

    public RCTAes(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "RCTAes";
    }

    @ReactMethod
    public void encrypt(String data, String keyBase64, String ivBase64, Promise promise) {
        try {
            String result = encrypt(data, keyBase64, ivBase64);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void encryptBase64(String dataBase64, String keyBase64, String ivBase64, Promise promise) {
        try {
            String result = encryptBase64(dataBase64, keyBase64, ivBase64);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void decrypt(String data, String pwd, String iv, Promise promise) {
        try {
            String strs = decrypt(data, pwd, iv);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void pbkdf2(String pwd, String salt, Integer cost, Integer length, Promise promise) {
        try {
            String strs = pbkdf2(pwd, salt, cost, length);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void hmac256(String data, String pwd, Promise promise) {
        try {
            String strs = hmac256(data, pwd);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void sha256(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-256");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void sha1(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-1");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void sha512(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-512");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void randomUuid(Promise promise) {
        try {
            String result = UUID.randomUUID().toString();
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void randomKey(Integer length, Promise promise) {
        try {
            byte[] keyData = new byte[length];
            SecureRandom rand = new SecureRandom();
            rand.nextBytes(keyData);
            String key = Base64.encodeToString(keyData, Base64.NO_WRAP);
            promise.resolve(key);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    private String shaX(String data, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(data.getBytes());
        byte[] digest = md.digest();
        return Base64.encodeToString(digest, Base64.NO_WRAP);
    }

    private static String pbkdf2(String pwd, String salt, Integer cost, Integer length)
    throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(pwd.getBytes(StandardCharsets.UTF_8), Base64.decode(salt, Base64.NO_WRAP), cost);
        byte[] key = ((KeyParameter) gen.generateDerivedParameters(length)).getKey();
        return Base64.encodeToString(key, Base64.NO_WRAP);
    }

    private static String hmac256(String text, String key) throws NoSuchAlgorithmException, InvalidKeyException  {
        byte[] contentData = text.getBytes(StandardCharsets.UTF_8);
        byte[] keyData = Base64.decode(key, Base64.NO_WRAP);
        Mac sha256_HMAC = Mac.getInstance(HMAC_SHA_256);
        SecretKey secret_key = new SecretKeySpec(keyData, HMAC_SHA_256);
        sha256_HMAC.init(secret_key);
        return Base64.encodeToString(sha256_HMAC.doFinal(contentData), Base64.NO_WRAP);
    }

    final static IvParameterSpec emptyIvSpec = new IvParameterSpec(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

    private static String encrypt(String text, String base64Key, String base64IV) throws Exception {
        if (text == null || text.length() == 0) {
            return null;
        }

        byte[] key = Base64.decode(base64Key, Base64.NO_WRAP);
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, base64IV == null ? emptyIvSpec : new IvParameterSpec(Base64.decode(base64IV, Base64.NO_WRAP)));
        byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));
        return Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }

    private static String encryptBase64(String base64Text, String base64Key, String base64IV) throws Exception {
        if (base64Text == null || base64Text.length() == 0) {
            return null;
        }

        byte[] key = Base64.decode(base64Key, Base64.NO_WRAP);
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, base64IV == null ? emptyIvSpec : new IvParameterSpec(Base64.decode(base64IV, Base64.NO_WRAP)));
        byte[] encrypted = cipher.doFinal(Base64.decode(base64Text, Base64.NO_WRAP));
        return Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }

    private static String decrypt(String ciphertext, String base64Key, String base64IV) throws Exception {
        if(ciphertext == null || ciphertext.length() == 0) {
            return null;
        }

        byte[] key = Base64.decode(base64Key, Base64.NO_WRAP);
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, base64IV == null ? emptyIvSpec : new IvParameterSpec(Base64.decode(base64IV, Base64.NO_WRAP)));
        byte[] decrypted = cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP));
        return new String(decrypted, "UTF-8");
    }

}
