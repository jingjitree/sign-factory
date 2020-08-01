package top.inson.api.core.impl;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import top.inson.api.constants.RSAConstants;
import top.inson.api.core.IRSASHA256withRSAFactory;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class RSASHA256withRSAFactoryImpl extends RSASignFactoryImpl implements IRSASHA256withRSAFactory {

    @Override
    public String sign(String sourceData, String privateKey) throws Exception {
        /*
        //摘要算法
        MessageDigest messageDigest = MessageDigest.getInstance(encodeAlgorithms);
        messageDigest.update(sourceData.getBytes());
        byte[] digest = messageDigest.digest();
        */
        PrivateKey priKey = getPrivateKey(privateKey);
        Signature signature = Signature.getInstance(RSAConstants.SIGN_SHA256RSA_ALGORITHMS);
        signature.initSign(priKey);
        signature.update(sourceData.getBytes());
        byte[] sign = signature.sign();
        return Base64.encodeBase64String(sign);
    }

    @Override
    public boolean verify(String sourceData, String encryptData, String publicKey) throws Exception {
        /*
        //填充
        MessageDigest messageDigest = MessageDigest.getInstance(encodeAlgorithms);
        messageDigest.update(sourceData.getBytes());
        byte[] digest = messageDigest.digest();
        */
        PublicKey pubKey = getPublicKey(publicKey);
        Signature signature = Signature.getInstance(RSAConstants.SIGN_SHA256RSA_ALGORITHMS);
        signature.initVerify(pubKey);
        signature.update(sourceData.getBytes());
        byte[] encrypt = Base64.decodeBase64(encryptData.getBytes());
        return signature.verify(encrypt);
    }
}
