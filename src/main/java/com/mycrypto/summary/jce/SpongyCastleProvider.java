package com.mycrypto.summary.jce;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * Created by TF016591 on 2018/3/28.
 */
public class SpongyCastleProvider {
    private static class Holder {
        private static final Provider INSTANCE;
        static{
            Provider p = Security.getProvider("SC");

            INSTANCE = (p != null) ? p : new BouncyCastleProvider();

            INSTANCE.put("MessageDigest.ETH-KECCAK-256", "com.mycrypto.summary.cryptohash.Keccak256");
            INSTANCE.put("MessageDigest.ETH-KECCAK-512", "com.mycrypto.summary.cryptohash.Keccak512");
        }
    }

    public static Provider getInstance() {
        return Holder.INSTANCE;
    }
}
