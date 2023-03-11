package org.example;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.example.exceptions.SignatureVerificationException;
import org.example.exceptions.SigningException;

public class SigningUtilities {

    public static byte[] digestData(byte[] data) throws IOException {

        SHA256Digest messageDigest = new SHA256Digest();

        byte[] digested = new byte[messageDigest.getDigestSize()];

        messageDigest.update(data, 0, data.length);
        messageDigest.doFinal(digested, 0);

        return digested;
    }

    public static byte[] signData(byte[] data, PrivateKey signerKey, X509Certificate signerCertificate) throws OperatorCreationException, CertificateEncodingException, SigningException {
        List<X509Certificate> certList= new ArrayList<X509Certificate>();
        certList.add(signerCertificate);

        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        byte[] signature;

        // Operações relacionadas ao CMSSignedDataGenerator

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(signerKey);
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(contentSigner, signerCertificate));

        Store certs = new JcaCertStore(certList);

        try {
            cmsGenerator.addCertificates(certs);
            // Gerando a assinatura de acordo com padrão CMS
            CMSSignedData cms = cmsGenerator.generate(cmsData, true);
            // Obtendo representação ASN.1 da assinatura
            signature = cms.getEncoded();
        } catch (CMSException | IOException e) {
            throw new SigningException("CMS signature generation failure.", e);
        }

        return signature;
    }

    public static boolean verifySignature(byte[] data) throws CMSException, IOException, CertificateException,
            OperatorCreationException, SignatureVerificationException {

        X509Certificate signCert = null;
        CMSSignedData cmsSignedData = null;

        // Convertendo signedData para ASN1InputStream
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);

        cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asnInputStream.readObject()));

        // Obtendo todos os assinantes da mensagem assinada cmsSignedData
        SignerInformationStore signers = cmsSignedData.getSignerInfos();

        // Como já espera-se que seja apenas um assinante, não vamos iterar a coleção
        SignerInformation signer = signers.getSigners().iterator().next();

        Collection<X509CertificateHolder> certCollection = cmsSignedData.getCertificates().getMatches(signer.getSID());

        X509CertificateHolder certHolder = certCollection.iterator().next();

        try {
            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
        } catch (CMSException e) {
            throw new SignatureVerificationException("An error occurred while verifying the signature.", e);
        } catch (CertificateException e) {
            throw e;
        }
    }

    public static SignerCertKey loadCertKeyFromPKCS12(byte[] pkcs12Bytes, String alias, char[] password) throws
            NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        InputStream pkcs12InputStream = new ByteArrayInputStream(pkcs12Bytes);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(pkcs12InputStream, password);

//        Iterator<String> itAliases = keyStore.aliases().asIterator();
//        while (itAliases.hasNext()) {
//            System.out.println(itAliases.next());
//        }

        // Recuperando a chave privada e o certificado da entidade assinante
        PrivateKey signerKey = (PrivateKey) keyStore.getKey(alias, password);
        X509Certificate signerCertificate = (X509Certificate) keyStore.getCertificate(alias);

        return new SignerCertKey(signerCertificate, signerKey);
    }
}