package top.inson.api.core;

public interface IMd5SignFactory extends ISignFactory{

    String md5Sign(String source);

    boolean verifyMd5(String source, String signStr);

}
