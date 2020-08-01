package top.inson.api.core;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface IRSASignFactory extends ISignFactory{

    String rsaPublicEncrypt(String sourceData, String publicKey) throws Exception;

    String rsaPrivateDecrypt(String encryptData, String privateKey) throws Exception;

    String rsaPrivateEncrypt(String sourceData, String privateKey) throws Exception;

    String rsaPublicDecrypt(String encryptData, String publicKey) throws Exception;

    String rsaEncrypt(String sourceData, String keyStr, boolean isPrivateKey) throws Exception;

    String rsaDecrypt(String encryptData, String keyStr, boolean isPrivateKey) throws Exception;

    PrivateKey getPrivateKey(String privateKey) throws Exception;

    PublicKey getPublicKey(String publicKey) throws Exception;

}
