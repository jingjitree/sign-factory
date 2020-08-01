package top.inson.api.core;

public interface IRSASHA256withRSAFactory extends IRSASignFactory{

    String sign(String sourceData, String privateKey, String encodeAlgorithms) throws Exception;

    boolean verify(String sourceData, String encryptData, String publicKey, String encodeAlgorithms) throws Exception;

}
