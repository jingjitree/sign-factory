package top.inson.api.core;

import java.security.Signature;

public interface ISHA1withRSAFactory extends IRSASignFactory{

    String sign(String sourceData, String privateKey) throws Exception;

    boolean verifySign(String sourceData, String encryptData, String publicKey) throws Exception;

}
