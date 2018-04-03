package com.mycrypto.certificate;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;

/**
 * Created by TF016591 on 2018/4/2.
 */
public class PEMCoder {
    /**获取keyPair
     * @throws IOException */
    public static KeyPair readkeypKeyPair(String  pemPath,String password) throws IOException{
        FileReader in=new FileReader(new File(pemPath));
        //构建PEMParser解析类
        PEMReader reader = new PEMReader(in,new MyPassFinder(password));
        KeyPair keyPair = (KeyPair) reader.readObject();
        reader.close();
        in.close();
        return keyPair;
    }
}
class MyPassFinder implements PasswordFinder{
    private String password="";

    public MyPassFinder(){
    }

    public MyPassFinder(String password){
        this.password=password;
    }
    @Override
    public char[] getPassword() {
        return password.toCharArray();
    }

}
