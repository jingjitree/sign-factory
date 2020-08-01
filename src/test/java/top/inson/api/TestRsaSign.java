package top.inson.api;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import top.inson.api.core.IRSASHA256withRSAFactory;
import top.inson.api.core.IRSASignFactory;
import top.inson.api.core.ISHA1withRSAFactory;
import top.inson.api.core.impl.RSASHA256withRSAFactoryImpl;
import top.inson.api.core.impl.RSASignFactoryImpl;
import top.inson.api.core.impl.SHA1withRSAFactoryImpl;


public class TestRsaSign {
    private static final Log log = LogFactory.getLog(TestRsaSign.class);

    @Test
    public void trimSpace(){
        String str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwr7GHhcQAVOl5QzmSkSU\n" +
                "hzOAFZYztIXcktjlv0se59MnwuWwmyoz5HB7QmLN3L4K6IU7PjXWKb+Wr/nJuZEX\n" +
                "dRDnPpO1z/rG8RM3nNh6gYOFRQqf1PAeXGh367kDfSS04n/MwKyurgZuG2hbKfD+\n" +
                "MMxoy1qrIWuMETLs3UNo+zmJX4irexZd1DG6S8Q/NdKtY9/XpApoT0jh+ra3zTkB\n" +
                "l1trPYpMgAgSRuLodjUIRyOfkI9PoYc9k7S+mprE7Mc2EijGtrh9cgwqGe9pzQ4U\n" +
                "mSJkuleKN3gMher2ORtODoLkqT3WlKnWydOb3zB0JWdAZP4Qutb5nlnqpvuxnCEL\n" +
                "BQIDAQAB";
        log.info(str.replaceAll("\n", ""));
    }


    @Test
    public void testRsa(){
        String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMB0a1Ti9vG7WYhVyC1X7X21LhhRBQhgcmoLN9Dqm21TBNjB0Lmu+2FRHguzQ6vaEat8JD4p6ebZ/FW3DV3lBRa/Nkuu0KPFlqne/v1uX4KvHcjyvDvopjIOQXgbKe3O9XcllYN1rkKgJtwzzSnoaV0R8mXMwW+PNouzbz48XbY9AgMBAAECgYBVqz0f80xDvMcVFkJeVNal76HONzqLSQuFQusct2Jqntr4dgYosci6wDYktS65cAAPmtozRcsV9RELQsnTcx/5AxKMEkLm9/YFY6LEcpt+88oOA04fT3CMhSpQlb+ub2DjDgx/a0B0/FadfFgeV6iCeD5h4bORVTC/MEhwMT5F7QJBAO6OICSTu3QvF65H0b4BkxCWievPHweb1hvSqz/2UNqublOtVrrYXz1F3Q43qsclTm7TgrIjLKF2lmwZFIvtH9MCQQDOh0U8TiYYy60HKdPB/PS5U+vsIl1ETqO/neqqST4RKajxOI1Cd3bvVH91bK+LfcwPxuWPcGJa3oTZnUFyUxevAkEAlGkPTjIqeMmjbeV4c0D/gV5mR7H/l/g3Z+/UYmKXQrUqJhy8zFk4RyJjuCihsmtfNEuaD8EaTwk749xmj/bhyQJAZpaW86+2CNcTad2DDHdEcNKY/EDNp2KQwFwG9vNO22OgQcJfmMaS06tbbM7CHD4uoR+hZDDlClJCF36fxdQ0jQJAfZORAGpguQfBG+n0W968TXepx3xpzShDWiv+QPnb/QsRkbEsoXTKSQOqAPtKL222JUdyAQEhuTJGt8dTUGIF0Q==";
        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAdGtU4vbxu1mIVcgtV+19tS4YUQUIYHJqCzfQ6pttUwTYwdC5rvthUR4Ls0Or2hGrfCQ+Kenm2fxVtw1d5QUWvzZLrtCjxZap3v79bl+Crx3I8rw76KYyDkF4GyntzvV3JZWDda5CoCbcM80p6GldEfJlzMFvjzaLs28+PF22PQIDAQAB";

        IRSASignFactory rsaSignFactory = new RSASignFactoryImpl();
        try {
            //私钥加密，公钥解密
            String encrypt = rsaSignFactory.rsaPrivateEncrypt("123456", privateKey);
            log.info(encrypt);
            String source = rsaSignFactory.rsaPublicDecrypt(encrypt, publicKey);
            log.info(source);
            //公钥加密，私钥解密
            String encrypt2 = rsaSignFactory.rsaPublicEncrypt("shihuai123456", publicKey);
            log.info("encrypt2:" + encrypt2);
            String source2 = rsaSignFactory.rsaPrivateDecrypt(encrypt2, privateKey);
            log.info("source2:" + source2);
        } catch (Exception e) {
            log.error("加解密异常", e);
        }
    }

    @Test
    public void testRSA2(){
        String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCvsYeFxABU6XlDOZKRJSHM4AVljO0hdyS2OW/Sx7n0yfC5bCbKjPkcHtCYs3cvgrohTs+NdYpv5av+cm5kRd1EOc+k7XP+sbxEzec2HqBg4VFCp/U8B5caHfruQN9JLTif8zArK6uBm4baFsp8P4wzGjLWqsha4wRMuzdQ2j7OYlfiKt7Fl3UMbpLxD810q1j39ekCmhPSOH6trfNOQGXW2s9ikyACBJG4uh2NQhHI5+Qj0+hhz2TtL6amsTsxzYSKMa2uH1yDCoZ72nNDhSZImS6V4o3eAyF6vY5G04OguSpPdaUqdbJ05vfMHQlZ0Bk/hC61vmeWeqm+7GcIQsFAgMBAAECggEAFbEyWD+xZLRwkibxr+wbr0OpTL5CXCVdAG5wiPJRKvl2QFtdZKs6xINS934R+Dii9muAwdk1Vckle8yTD7x9pGiRmYLSiawhZNEDLNFgM/T2b05Tp2BnwVtRoEwne1UPYPtjT0Ls4i2NLjhdjzps1fqu4Zfj4AEexPurLqpHk1QPlbKUiqmWnS2ylj9FaSJvxpe4tdCKc7H0W11lRV8yAmdOInJXmZuCFrrJymtRxXmPFvO3iIiLgTh5HKpcDaHU70NgC+mniNIzr3C9ByQ3dOacb22wRXisw+uKwP6PkLM/DQhB/wKwQXe4X3pZ8/smdQYpJev3mUaM3RYYKxwJAQKBgQDoEPYWxgavWGvu3i7YTYKj63+twJdlWFIJkNeBmsTcdDK9jp11lYOamFsoYc8UBCHyiomXBW8Nm2+hJVOrDfMoo5nr1/eNT81ybWUoVGbfYcopcybMqv+p5SnoEfL+fX/LYSs6Q6xgEpuDHueqJiF3wMKIVjrqc8P/mW9ZY8IJ0QKBgQDW1HVTS8f08btsLxi13hP3wnU6qt/+v4qxOxlnMigjZeIaDbvP53ZzZSLgBRHId+nPO4Iyf8GjEqRraRepyrP64JcD2ugYBmjsFDALDJk6ybfZ/yfF/p697OmALUiN379a64QgVv90C4ZOFVXIyw1O4KtBRW3+/cNKu4ZE0fbG9QKBgQDbLVHPVn5v03o1I4Fo52Pwf3aaWyBiJlVtFXCExvERKWnW4EBVEr42H5lQ/Xe/9ts9IJ0sloQ5fMmkkAWCs+0pP8MbHWGABJQMc8ernHOAnPJ7zXcirIpFItw+g91VgKBXLNHP+KRwJILeBy1T5SmM2fChJZgFYQsHeBnTekWEUQKBgH5Ow/yJXbNCPTPKLPkg7RSKnGo19STOcTjqynDGKJtHV7yBvp7qM9Z87BhSYrY+6pURI+eU/cBnQYx1aZhGubMTQTbfCf62JhJHfEfCzISn/RSK1FOw9JwuIstd1H61wsguGKz6+Y69B+X43UsFN3nc1lO2AoodoSjbQIJOAI3RAoGAfV22sHAcpHRAdwJRMcVyHpg/gJpPSGJqqCn+g0MSv0iHIeII15Mr1i8UA32NFnS3U72Fgd2dyeyoXSgjrOiuVJNIVhKp2NeNNx8xCUM7xZSi7yImg2JdoIwV2FOpQMEC8EJpkQLJ+mm1y2iYg00EF7ihe2vgc8ntpO33/ITdovo=";
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwr7GHhcQAVOl5QzmSkSUhzOAFZYztIXcktjlv0se59MnwuWwmyoz5HB7QmLN3L4K6IU7PjXWKb+Wr/nJuZEXdRDnPpO1z/rG8RM3nNh6gYOFRQqf1PAeXGh367kDfSS04n/MwKyurgZuG2hbKfD+MMxoy1qrIWuMETLs3UNo+zmJX4irexZd1DG6S8Q/NdKtY9/XpApoT0jh+ra3zTkBl1trPYpMgAgSRuLodjUIRyOfkI9PoYc9k7S+mprE7Mc2EijGtrh9cgwqGe9pzQ4UmSJkuleKN3gMher2ORtODoLkqT3WlKnWydOb3zB0JWdAZP4Qutb5nlnqpvuxnCELBQIDAQAB";

        IRSASHA256withRSAFactory rsaFactory = new RSASHA256withRSAFactoryImpl();
        try {
            String sign = rsaFactory.sign("123456", privateKey);
            log.info("加密之后的数据sign:" + sign);
            boolean verify = rsaFactory.verify("123456", sign, publicKey);
            log.info(verify);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testRSA(){
        String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCvsYeFxABU6XlDOZKRJSHM4AVljO0hdyS2OW/Sx7n0yfC5bCbKjPkcHtCYs3cvgrohTs+NdYpv5av+cm5kRd1EOc+k7XP+sbxEzec2HqBg4VFCp/U8B5caHfruQN9JLTif8zArK6uBm4baFsp8P4wzGjLWqsha4wRMuzdQ2j7OYlfiKt7Fl3UMbpLxD810q1j39ekCmhPSOH6trfNOQGXW2s9ikyACBJG4uh2NQhHI5+Qj0+hhz2TtL6amsTsxzYSKMa2uH1yDCoZ72nNDhSZImS6V4o3eAyF6vY5G04OguSpPdaUqdbJ05vfMHQlZ0Bk/hC61vmeWeqm+7GcIQsFAgMBAAECggEAFbEyWD+xZLRwkibxr+wbr0OpTL5CXCVdAG5wiPJRKvl2QFtdZKs6xINS934R+Dii9muAwdk1Vckle8yTD7x9pGiRmYLSiawhZNEDLNFgM/T2b05Tp2BnwVtRoEwne1UPYPtjT0Ls4i2NLjhdjzps1fqu4Zfj4AEexPurLqpHk1QPlbKUiqmWnS2ylj9FaSJvxpe4tdCKc7H0W11lRV8yAmdOInJXmZuCFrrJymtRxXmPFvO3iIiLgTh5HKpcDaHU70NgC+mniNIzr3C9ByQ3dOacb22wRXisw+uKwP6PkLM/DQhB/wKwQXe4X3pZ8/smdQYpJev3mUaM3RYYKxwJAQKBgQDoEPYWxgavWGvu3i7YTYKj63+twJdlWFIJkNeBmsTcdDK9jp11lYOamFsoYc8UBCHyiomXBW8Nm2+hJVOrDfMoo5nr1/eNT81ybWUoVGbfYcopcybMqv+p5SnoEfL+fX/LYSs6Q6xgEpuDHueqJiF3wMKIVjrqc8P/mW9ZY8IJ0QKBgQDW1HVTS8f08btsLxi13hP3wnU6qt/+v4qxOxlnMigjZeIaDbvP53ZzZSLgBRHId+nPO4Iyf8GjEqRraRepyrP64JcD2ugYBmjsFDALDJk6ybfZ/yfF/p697OmALUiN379a64QgVv90C4ZOFVXIyw1O4KtBRW3+/cNKu4ZE0fbG9QKBgQDbLVHPVn5v03o1I4Fo52Pwf3aaWyBiJlVtFXCExvERKWnW4EBVEr42H5lQ/Xe/9ts9IJ0sloQ5fMmkkAWCs+0pP8MbHWGABJQMc8ernHOAnPJ7zXcirIpFItw+g91VgKBXLNHP+KRwJILeBy1T5SmM2fChJZgFYQsHeBnTekWEUQKBgH5Ow/yJXbNCPTPKLPkg7RSKnGo19STOcTjqynDGKJtHV7yBvp7qM9Z87BhSYrY+6pURI+eU/cBnQYx1aZhGubMTQTbfCf62JhJHfEfCzISn/RSK1FOw9JwuIstd1H61wsguGKz6+Y69B+X43UsFN3nc1lO2AoodoSjbQIJOAI3RAoGAfV22sHAcpHRAdwJRMcVyHpg/gJpPSGJqqCn+g0MSv0iHIeII15Mr1i8UA32NFnS3U72Fgd2dyeyoXSgjrOiuVJNIVhKp2NeNNx8xCUM7xZSi7yImg2JdoIwV2FOpQMEC8EJpkQLJ+mm1y2iYg00EF7ihe2vgc8ntpO33/ITdovo=";
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwr7GHhcQAVOl5QzmSkSUhzOAFZYztIXcktjlv0se59MnwuWwmyoz5HB7QmLN3L4K6IU7PjXWKb+Wr/nJuZEXdRDnPpO1z/rG8RM3nNh6gYOFRQqf1PAeXGh367kDfSS04n/MwKyurgZuG2hbKfD+MMxoy1qrIWuMETLs3UNo+zmJX4irexZd1DG6S8Q/NdKtY9/XpApoT0jh+ra3zTkBl1trPYpMgAgSRuLodjUIRyOfkI9PoYc9k7S+mprE7Mc2EijGtrh9cgwqGe9pzQ4UmSJkuleKN3gMher2ORtODoLkqT3WlKnWydOb3zB0JWdAZP4Qutb5nlnqpvuxnCELBQIDAQAB";

        ISHA1withRSAFactory rsaFactory = new SHA1withRSAFactoryImpl();
        try {
            String sign = rsaFactory.sign("123456", privateKey);
            log.info("签名后数据sign：" + sign);
            boolean verify = rsaFactory.verifySign("123456", sign, publicKey);
            log.info(verify);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
