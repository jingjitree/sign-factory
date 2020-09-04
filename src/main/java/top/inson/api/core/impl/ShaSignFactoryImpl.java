package top.inson.api.core.impl;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import top.inson.api.core.IShaSignFactory;

public class ShaSignFactoryImpl implements IShaSignFactory {

    @Override
    public String sha1Sign(String source) throws Exception {
        if(StringUtils.isEmpty(source))
            return null;
        return DigestUtils.sha1Hex(source);
    }

    @Override
    public String sha256Sign(String source) throws Exception {
        if(StringUtils.isEmpty(source))
            return null;
        return DigestUtils.sha256Hex(source);
    }

}
