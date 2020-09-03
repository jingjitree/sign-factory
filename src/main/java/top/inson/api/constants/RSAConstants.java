package top.inson.api.constants;

public final class RSAConstants {
    private RSAConstants(){

    }

    public static final String SIGN_TYPE_RSA = "RSA";
    public static final String SIGN_TYPE_RSA2 = "RSA2";
    /**
     * RSA最大加密明文大小
     */
    public static final int MAX_RSA_ENCRYPT_BLOCK = 117;
    /**
     * RSA最大解密明文大小
     */
    public static final int MAX_RSA_DECRYPT_BLOCK = 128;
    public static final String SIGN_RSA_ALGORITHMS = "RSA";
    public static final String SIGN_SHA1RSA_ALGORITHMS = "SHA1WithRSA";
    public static final String SIGN_SHA256RSA_ALGORITHMS = "SHA256WithRSA";

    public static final int KEY_SIZE_1024 = 1024;
    public static final int KEY_SIZE_2048 = 2048;


}
