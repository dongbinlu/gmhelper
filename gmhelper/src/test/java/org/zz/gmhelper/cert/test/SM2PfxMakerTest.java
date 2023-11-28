package org.zz.gmhelper.cert.test;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.*;
import org.zz.gmhelper.test.util.FileUtil;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

public class SM2PfxMakerTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String TEST_PFX_PASSWD = "12345678";
    private static final String TEST_PFX_FILENAME = "target/test.pfx";


    /**
     * PFX（Personal Exchange Format）是一种证书文件格式，通常用于存储证书、私钥和证书链的安全容器。PFX 文件可以包含证书链，但不一定总是包含完整的证书链。
     *
     * 一个 PFX 文件可以包含：
     *
     * 1. **证书：** 用于标识实体（如服务器或个人）的数字证书。
     * 2. **私钥：** 与证书相关联的私钥，用于证书验证和安全通信。
     * 3. **证书链：** 一系列证书，形成了验证证书的链条。在某些情况下，PFX 文件中可能包含完整的证书链，但并非必须。
     *
     * 证书链是一组证书，从服务端证书直到根证书，依次连接并构建了信任链。对于客户端来说，完整的证书链有助于验证服务器提供的证书的合法性和可信度。
     * 有些PFX文件可能包含所有需要的中间证书以构建完整的证书链，而其他可能只包含单个实体的证书和私钥。
     *
     * 因此，尽管 PFX 文件通常用于包含证书、私钥和证书链，但要确定其是否包含完整的证书链，可能需要打开文件或使用特定的工具来查看其中的内容。
     */
    @Test
    public void testMakePfx() {
        try {
            KeyPair subKP = SM2Util.generateKeyPair();

            X500Name subDN = SM2X509CertMakerTest.buildSubjectDN();

            SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
                (BCECPublicKey) subKP.getPublic());

            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
                SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();

            SM2X509CertMaker certMaker = SM2X509CertMakerTest.buildCertMaker();
            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);

            SM2PfxMaker pfxMaker = new SM2PfxMaker();
            PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
            PublicKey subPub = BCECUtil.createPublicKeyFromSubjectPublicKeyInfo(request.getSubjectPublicKeyInfo());
            PKCS12PfxPdu pfx = pfxMaker.makePfx(subKP.getPrivate(), subPub, cert, TEST_PFX_PASSWD);
            byte[] pfxDER = pfx.getEncoded(ASN1Encoding.DER);
            FileUtil.writeFile(TEST_PFX_FILENAME, pfxDER);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testPfxSign() {
        //先生成一个pfx
        testMakePfx();

        try {
            byte[] pkcs12 = FileUtil.readFile(TEST_PFX_FILENAME);
            BCECPublicKey publicKey = SM2CertUtil.getPublicKeyFromPfx(pkcs12, TEST_PFX_PASSWD);
            BCECPrivateKey privateKey = SM2CertUtil.getPrivateKeyFromPfx(pkcs12, TEST_PFX_PASSWD);

            String srcData = "1234567890123456789012345678901234567890";
            byte[] sign = SM2Util.sign(privateKey, srcData.getBytes());
            boolean flag = SM2Util.verify(publicKey, srcData.getBytes(), sign);
            if (!flag) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}
