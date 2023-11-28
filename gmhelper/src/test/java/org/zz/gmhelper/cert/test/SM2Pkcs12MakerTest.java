package org.zz.gmhelper.cert.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.CommonUtil;
import org.zz.gmhelper.cert.SM2Pkcs12Maker;
import org.zz.gmhelper.cert.SM2PublicKey;
import org.zz.gmhelper.cert.SM2X509CertMaker;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.X509Certificate;

/**
 * @author Lijun Liao https:/github.com/xipki
 */
public class SM2Pkcs12MakerTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final char[] TEST_P12_PASSWD = "12345678".toCharArray();
    private static final String TEST_P12_FILENAME = "target/test.p12";

    /**
     * PKCS#12是一种密码学标准，用于存储和传输包含私钥、证书链和受保护数据的信息。它通常使用PFX（Personal Exchange Format）文件格式进行存储，PFX是PKCS#12标准的一种实现。
     * <p>
     * PKCS#12标准定义了一种可移植的格式，用于将证书、私钥和其他私密信息（如密码）存储在一个加密的文件中。这种文件可以轻松地在不同的系统之间共享，并提供了一种保护这些私密信息的方法。
     * <p>
     * 一般来说，PKCS#12（或PFX）文件可以包含以下内容：
     * <p>
     * 1. **证书：** 用于身份验证和加密通信的数字证书。
     * 2. **私钥：** 与证书相关联的私钥，用于对通信进行加密和签名。
     * 3. **证书链：** 中间CA证书链，用于验证证书的合法性。
     * 4. **密码或其他敏感信息：** 这些信息可能包括用于保护PKCS#12文件的密码，或者其他私密数据。
     * <p>
     * PKCS#12文件的安全性建立在对文件本身的加密，需要使用密码来访问其中的内容。它在许多情况下被用于在安全的方式下共享证书和私钥，特别是在Web服务器配置、客户端身份验证和安全通信中。
     */
    @Test
    public void testMakePkcs12() {
        try {
            KeyPair subKP = SM2Util.generateKeyPair();

            X500Name subDN = SM2X509CertMakerTest.buildSubjectDN();

            SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
                    (BCECPublicKey) subKP.getPublic());

            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
                    SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();

            SM2X509CertMaker certMaker = SM2X509CertMakerTest.buildCertMaker();

            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);

            SM2Pkcs12Maker pkcs12Maker = new SM2Pkcs12Maker();
            KeyStore pkcs12 = pkcs12Maker.makePkcs12(subKP.getPrivate(), cert, TEST_P12_PASSWD);

            try (OutputStream os = Files.newOutputStream(Paths.get(TEST_P12_FILENAME),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
                pkcs12.store(os, TEST_P12_PASSWD);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testPkcs12Sign() {
        //先生成一个pkcs12
        testMakePkcs12();

        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            try (InputStream is = Files.newInputStream(Paths.get(TEST_P12_FILENAME),
                    StandardOpenOption.READ)) {
                ks.load(is, TEST_P12_PASSWD);
            }

            PrivateKey privateKey = (BCECPrivateKey) ks.getKey("User Key", TEST_P12_PASSWD);
            X509Certificate cert = (X509Certificate) ks.getCertificate("User Key");

            byte[] srcData = "1234567890123456789012345678901234567890".getBytes();


            // create signature
            Signature sign = Signature.getInstance(SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2, "BC");
            sign.initSign(privateKey);
            sign.update(srcData);
            byte[] signatureValue = sign.sign();

            // verify signature
            Signature verify = Signature.getInstance(SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2, "BC");
            verify.initVerify(cert);
            verify.update(srcData);
            boolean sigValid = verify.verify(signatureValue);
            Assert.assertTrue("signature validation result", sigValid);


            /*
            byte[] signatureValue = SM2Util.sign((BCECPrivateKey) privateKey, srcData);

            boolean sigValid = SM2Util.verify((BCECPublicKey) cert.getPublicKey(), srcData, signatureValue);

            if (!sigValid){
                Assert.fail();
            }*/

        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}
