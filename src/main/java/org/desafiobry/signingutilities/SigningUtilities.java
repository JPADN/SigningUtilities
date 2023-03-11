package org.desafiobry.signingutilities;

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
import org.desafiobry.exceptions.SignatureVerificationException;
import org.desafiobry.exceptions.SigningException;

public class SigningUtilities {

    // digestData produz um resumo criptográfico de 'data' utilizando o algoritmo SHA-256
    public static byte[] digestData(byte[] data) throws IOException {

        SHA256Digest messageDigest = new SHA256Digest();

        byte[] digested = new byte[messageDigest.getDigestSize()];

        messageDigest.update(data, 0, data.length);
        messageDigest.doFinal(digested, 0);

        return digested;
    }

    // signData assina o conteúdo de 'data' utilizando a chave privada 'signerKey' e o certificado correspondente 'signerCertificate'
    public static byte[] signData(byte[] data, PrivateKey signerKey, X509Certificate signerCertificate) throws OperatorCreationException, CertificateEncodingException, SigningException {
        List<X509Certificate> certList= new ArrayList<X509Certificate>();
        certList.add(signerCertificate);

        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        byte[] signature;

        // Operações relacionadas ao CMSSignedDataGenerator

        // Construindo um objeto do tipo ContentSigner para assinaturas com o algoritmo RSA (utilizando algoritmo de hash SHA-256) com a chave privada 'signerKey'
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(signerKey);

        // Adicionando informações do assinante: o objeto contentSigner (que contém a chave privada signerKey) e o seu certificado 'signerCertificate'.
        // "BC" corresponde ao Security Provider "Bouncy Castle"
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(contentSigner, signerCertificate));

        Store certs = new JcaCertStore(certList);

        try {
            // Adicionando os certificados que serão anexados à assinatura
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

    // verifySignature verificate a assinatura CMS em data, retornando true para assinaturas válidas e false para assinaturas inválidas.
    public static boolean verifySignature(byte[] data) throws CMSException, IOException, CertificateException,
            OperatorCreationException, SignatureVerificationException {

        CMSSignedData cmsSignedData;

        // Convertendo byte array para ASN1InputStream
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);

        cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asnInputStream.readObject()));

        // Obtendo todos os assinantes da mensagem assinada cmsSignedData
        SignerInformationStore signers = cmsSignedData.getSignerInfos();

        // Como já espera-se que seja apenas um assinante, não vamos iterar a coleção inteira, apenas vamos recuperar o primeiro elemento desta.
        SignerInformation signer = signers.getSigners().iterator().next();

        // Recuperando o certificado X509 da Store retornada por getCertificates que corresponde ao SID do assinante.
        Collection<X509CertificateHolder> certCollection = cmsSignedData.getCertificates().getMatches(signer.getSID());

        // certHolder é o certificado X509 do assinante.
        X509CertificateHolder certHolder = certCollection.iterator().next();

        try {
            // Fazendo a verificação da assinatura constante no objeto signer (tipo SignerInformation) com o certificado X509 (visto que
            // este contem a chave pública para verificação).
            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
        } catch (CMSException e) {
            throw new SignatureVerificationException("An error occurred while verifying the signature.", e);
        }
    }

    // loadCertKeyFromPKCS12 retorna o certificado X509 e a chave privada armazenadas em um arquivo PKCS#12 (cujos bytes estão
    // em 'pkcs12Bytes') sob o alias 'alias' e protegidos com a senha 'password'.
    // É retornado um objeto do tipo SignerCertKey, que contém os campos 'x509Certificate' e 'privateKey'.
    public static SignerCertKey loadCertKeyFromPKCS12(byte[] pkcs12Bytes, String alias, char[] password) throws
            NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        InputStream pkcs12InputStream = new ByteArrayInputStream(pkcs12Bytes);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(pkcs12InputStream, password);

        // Recuperando a chave privada e o certificado da entidade assinante
        PrivateKey signerKey = (PrivateKey) keyStore.getKey(alias, password);
        X509Certificate signerCertificate = (X509Certificate) keyStore.getCertificate(alias);

        return new SignerCertKey(signerCertificate, signerKey);
    }
}