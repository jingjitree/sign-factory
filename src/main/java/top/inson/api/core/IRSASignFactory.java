package top.inson.api.core;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

public interface IRSASignFactory extends ISignFactory{

    String rsaPublicEncrypt(String sourceData, String publicKey) throws Exception;

    String rsaPrivateDecrypt(String encryptData, String privateKey) throws Exception;

    String rsaPrivateEncrypt(String sourceData, String privateKey) throws Exception;

    String rsaPublicDecrypt(String encryptData, String publicKey) throws Exception;

    String rsaEncrypt(String sourceData, String keyStr, boolean isPrivateKey) throws Exception;

    String rsaDecrypt(String encryptData, String keyStr, boolean isPrivateKey) throws Exception;

    PrivateKey getPrivateKey(String privateKey) throws Exception;

    PublicKey getPublicKey(String publicKey) throws Exception;

    /**
     * 生成rsa密钥对
     * @param keySize 密钥长度
     * @return
     * @throws Exception
     */
    Map<String, Object> generatorRsaKeyPair(int keySize) throws Exception;

    boolean generatorRsaKeyFile(int keySize, String filePath) throws Exception;

}
