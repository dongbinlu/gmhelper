package org.zz.gmhelper.cert;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.zz.gmhelper.cert.exception.InvalidX500NameException;

import java.security.PrivateKey;
import java.util.Iterator;
import java.util.Map;

public class CommonUtil {
    /**
     * 如果不知道怎么填充names，可以查看org.bouncycastle.asn1.x500.style.BCStyle这个类，
     * names的key值必须是BCStyle.DefaultLookUp中存在的（可以不关心大小写）
     *
     * X500Name 是 Java 中用来表示 X.500 标准中定义的名称（比如用于证书中的主题和颁发者名称）的类。在数字证书中，这个类通常用于表示证书中的主体（subject）和颁发者（issuer）信息，包括名称、组织单位、国家等。
     *
     * 这个类可以用来构建和解析证书的 DN（Distinguished Name），也就是证书中用来标识唯一主体或颁发者的部分。例如，在创建证书请求时，你可以使用 X500Name 来指定要包含在证书中的主题信息。在验证证书时，可以使用 X500Name 对象来比较颁发者和主体信息，以确认证书的合法性。
     *
     * 一般来说，X500Name 提供了一种方便的方式来处理和操作证书中的标准化名称信息，确保了证书中的身份和信息的唯一性和标准性。
     *
     * @param names
     * @return
     * @throws InvalidX500NameException
     */
    public static X500Name buildX500Name(Map<String, String> names) throws InvalidX500NameException {
        if (names == null || names.size() == 0) {
            throw new InvalidX500NameException("names can not be empty");
        }
        try {
            X500NameBuilder builder = new X500NameBuilder();
            Iterator itr = names.entrySet().iterator();
            BCStyle x500NameStyle = (BCStyle) BCStyle.INSTANCE;
            Map.Entry entry;
            while (itr.hasNext()) {
                entry = (Map.Entry) itr.next();
                ASN1ObjectIdentifier oid = x500NameStyle.attrNameToOID((String) entry.getKey());
                builder.addRDN(oid, (String) entry.getValue());
            }
            return builder.build();
        } catch (Exception ex) {
            throw new InvalidX500NameException(ex.getMessage(), ex);
        }
    }


    /**
     * 生成CSR
     *
     * @param subject  主题信息
     * @param pubKey   公钥
     * @param priKey   私钥
     * @param signAlgo 签名算法
     * @return CSR
     */
    public static PKCS10CertificationRequest createCSR(X500Name subject, SM2PublicKey pubKey, PrivateKey priKey,
                                                       String signAlgo) throws OperatorCreationException {
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, pubKey);
        ContentSigner signerBuilder = new JcaContentSignerBuilder(signAlgo)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(priKey);
        return csrBuilder.build(signerBuilder);
    }

    /**
     * 生成CSR
     * 实际业务大部部分情况私钥是在UKey中,只能调用UKey的签名接口,因此上面的方法不能使用,本方法是为了解决这个问题,从外部签名完毕,传入签名值就可以
     * 需要签名的对象为本方法中的 info ,取info.getEncoded()后签名
     * @param subject  主题信息
     * @param pubKey   公钥
     * @param signAlgo 签名算法
     * @param sign     签名值  对本方法中的 info ,取info.getEncoded()后签名
     * @return CSR
     */
    public static PKCS10CertificationRequest createCSR(X500Name subject, SM2PublicKey pubKey, String signAlgo, byte[] sign) throws OperatorCreationException {
        //info
        SM2PublicKey sm2SubPub = new SM2PublicKey(pubKey.getAlgorithm(), pubKey);
        ASN1EncodableVector v = new ASN1EncodableVector();
        CertificationRequestInfo info = new CertificationRequestInfo(subject, SubjectPublicKeyInfo.getInstance(sm2SubPub.getEncoded()), new DERSet(v));
        AlgorithmIdentifier algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(signAlgo);
        CertificationRequest certificationRequest = new CertificationRequest(info, algorithmIdentifier, new DERBitString(sign));
        return new PKCS10CertificationRequest(certificationRequest);
    }


    public static AlgorithmIdentifier findSignatureAlgorithmIdentifier(String algoName) {
        DefaultSignatureAlgorithmIdentifierFinder sigFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        return sigFinder.find(algoName);
    }

    public static AlgorithmIdentifier findDigestAlgorithmIdentifier(String algoName) {
        DefaultDigestAlgorithmIdentifierFinder digFinder = new DefaultDigestAlgorithmIdentifierFinder();
        return digFinder.find(findSignatureAlgorithmIdentifier(algoName));
    }
}
