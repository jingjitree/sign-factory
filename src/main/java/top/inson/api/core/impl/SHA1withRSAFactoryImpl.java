package top.inson.api.core.impl;

import org.apache.commons.codec.binary.Base64;
import top.inson.api.constants.RSAConstants;
import top.inson.api.core.ISHA1withRSAFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SHA1withRSAFactoryImpl extends RSASignFactoryImpl implements ISHA1withRSAFactory {

    @Override
    public String sign(String sourceData, String privateKey) throws Exception {
        PrivateKey priKey = getPrivateKey(privateKey);
        Signature signature = Signature.getInstance(RSAConstants.SIGN_SHA1RSA_ALGORITHMS);
        signature.initSign(priKey);
        signature.update(sourceData.getBytes());
        byte[] sign = signature.sign();
        return Base64.encodeBase64String(sign);
    }

    @Override
    public boolean verifySign(String sourceData, String encryptData, String publicKey) throws Exception {
        PublicKey pubKey = getPublicKey(publicKey);
        Signature signature = Signature.getInstance(RSAConstants.SIGN_SHA1RSA_ALGORITHMS);
        signature.initVerify(pubKey);
        signature.update(sourceData.getBytes());
        byte[] encrypt = Base64.decodeBase64(encryptData);
        return signature.verify(encrypt);
    }

}
