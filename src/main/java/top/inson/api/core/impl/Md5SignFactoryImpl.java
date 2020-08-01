package top.inson.api.core.impl;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import top.inson.api.core.IMd5SignFactory;

public class Md5SignFactoryImpl implements IMd5SignFactory {

    @Override
    public String md5Sign(String source) {
        if(StringUtils.isEmpty(source))
            return null;
        return DigestUtils.md5Hex(source);
    }

    @Override
    public boolean verifyMd5(String source, String signStr) {
        if(StringUtils.isEmpty(source) || StringUtils.isEmpty(signStr))
            return false;
        String code = md5Sign(source);
        return code.equals(signStr);
    }

}
