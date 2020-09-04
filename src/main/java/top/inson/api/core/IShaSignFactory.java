package top.inson.api.core;

public interface IShaSignFactory extends ISignFactory{

    String sha1Sign(String source) throws Exception;

    String sha256Sign(String source) throws Exception;

}
