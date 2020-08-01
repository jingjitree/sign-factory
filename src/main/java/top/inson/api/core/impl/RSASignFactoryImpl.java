package top.inson.api.core.impl;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;
import sun.plugin2.message.Message;
import top.inson.api.constants.RSAConstants;
import top.inson.api.core.IRSASignFactory;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSASignFactoryImpl implements IRSASignFactory {

    @Override
    public String rsaPublicEncrypt(String sourceData, String publicKey) throws Exception {
        return rsaEncrypt(sourceData, publicKey, false);
    }

    @Override
    public String rsaPrivateDecrypt(String encryptData, String privateKey) throws Exception {
        return rsaDecrypt(encryptData, privateKey, true);
    }

    @Override
    public String rsaPrivateEncrypt(String sourceData, String privateKey) throws Exception {
        return rsaEncrypt(sourceData, privateKey, true);
    }

    @Override
    public String rsaPublicDecrypt(String encryptData, String publicKey) throws Exception {
        return rsaDecrypt(encryptData, publicKey, false);
    }

    @Override
    public String rsaEncrypt(String sourceData, String keyStr, boolean isPrivateKey) throws Exception {
        Key key = isPrivateKey ? getPrivateKey(keyStr) : getPublicKey(keyStr);
        byte[] data = sourceData.getBytes();
        byte[] dataResult = new byte[0];
        int len = data.length;
        Cipher cipher = Cipher.getInstance(RSAConstants.SIGN_RSA_ALGORITHMS);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // 加密时超过117字节就报错。为此采用分段加密的办法来加密
        for (int i = 0; i < len; i += RSAConstants.MAX_RSA_ENCRYPT_BLOCK) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i,i + RSAConstants.MAX_RSA_ENCRYPT_BLOCK));
            dataResult = ArrayUtils.addAll(dataResult, doFinal);
        }
        return Base64.encodeBase64String(dataResult);
    }

    @Override
    public String rsaDecrypt(String encryptData, String keyStr, boolean isPrivateKey) throws Exception {
        Key key = isPrivateKey ? getPrivateKey(keyStr) : getPublicKey(keyStr);
        byte[] data = Base64.decodeBase64(encryptData);
        int len = data.length;
        Cipher cipher = Cipher.getInstance(RSAConstants.SIGN_RSA_ALGORITHMS);
        cipher.init(Cipher.DECRYPT_MODE, key);

        // 解密时超过128字节就报错。为此采用分段解密的办法来解密
        byte[] dataResult = new byte[0];
        for (int i = 0; i < len; i += RSAConstants.MAX_RSA_DECRYPT_BLOCK) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + RSAConstants.MAX_RSA_DECRYPT_BLOCK));
            dataResult = ArrayUtils.addAll(dataResult, doFinal);
        }
        return new String(dataResult);
    }

    @Override
    public PrivateKey getPrivateKey(String privateKey) throws Exception {
        byte[] buffer = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
        KeyFactory keyFactory = KeyFactory.getInstance(RSAConstants.SIGN_RSA_ALGORITHMS);
        return keyFactory.generatePrivate(keySpec);
    }

    @Override
    public PublicKey getPublicKey(String publicKey) throws Exception {
        byte[] buffer = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
        KeyFactory keyFactory = KeyFactory.getInstance(RSAConstants.SIGN_RSA_ALGORITHMS);
        return keyFactory.generatePublic(keySpec);
    }

}
