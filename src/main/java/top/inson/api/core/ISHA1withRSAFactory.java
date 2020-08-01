package top.inson.api.core;

public interface ISHA1withRSAFactory extends IRSASignFactory{

    String sign(String sourceData, String privateKey) throws Exception;

    boolean verifySign(String sourceData, String encryptData, String publicKey) throws Exception;

}
