package org.desafiobry;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.desafiobry.signingutilities.SignerCertKey;
import org.desafiobry.signingutilities.SigningUtilities;
import org.desafiobry.exceptions.EtapaDesafioException;
import org.desafiobry.exceptions.SignatureVerificationException;
import org.desafiobry.exceptions.SigningException;

import java.io.*;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Main {

    // Senha para acessar o arquivo PKCS#12 contido em resources/pkcs12.
    private final static String privateKeyPassword = "Bry123";
    // Alias sob o qual a chave privada e o certificado estão armazenados no arquivo PKCS#12.
    private final static String keystoreCertAlias = "4711a752-3249-4207-b039-d2bbeb7df38c";

    public static void main( String[] args )
    {
        Security.addProvider(new BouncyCastleProvider());
        DigestCalculatorProvider digestProvider = null;

        try {
            digestProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        } catch (OperatorCreationException e) {
            System.out.println("Could not build DigestCalculatorProvider from Bouncy Castle library");
            System.exit(1);
        }

        Main main = new Main();
        SigningUtilities signingUtilities = new SigningUtilities(new SHA256Digest(), "SHA256WithRSA",
                digestProvider);

        byte[] docBytes = null;
        byte[] pkcs12Bytes = null;
        byte[] signature = null;

        try {
            docBytes = main.getResourceBytes("arquivos/doc.txt");
            pkcs12Bytes = main.getResourceBytes("pkcs12/desafio.p12");
        } catch (IOException e) {
            System.exit(1);
        }

        try {
            // Etapa 1: Resumo criptográfico
            etapa1(signingUtilities, docBytes);
            System.out.println("Etapa 1 success!");
        } catch (EtapaDesafioException e) {
            System.out.printf("Etapa 1 error: %s\nEtapa 1 failed.\n\n%n", e.getMessage());
        }

        try {
            // Etapa 2: Realizar uma assinatura digital
            signature = etapa2(signingUtilities, docBytes, pkcs12Bytes);
            System.out.println("Etapa 2 success!");
        } catch (EtapaDesafioException e) {
            System.out.printf("Etapa 2 error: %s\nEtapa 2 failed. Skipping Etapa 3 due to Etapa 2 error...\nTerminating program.\n\n%n", e.getMessage());
            System.exit(1);
        }

        try {
            // Etapa 3: Verificar a assinatura gerada
            etapa3(signature);
            System.out.println("Etapa 3 success!");
        } catch (EtapaDesafioException e) {
            System.out.printf("Etapa 3 error: %s\nEtapa 3 failed.\n\n%n", e.getMessage());
        }
    }

    private static void etapa1(SigningUtilities signingUtilities, byte[] docBytes) throws EtapaDesafioException {

        byte[] digest;
        try {
            digest = signingUtilities.digestData(docBytes);
        } catch (IOException e) {
            throw new EtapaDesafioException("Could read the document's byte.", e);
        }

        String digestHexString = Hex.toHexString(digest);

        File digestOutputFile = FileUtils.getFile("output/doc_hex_digest.txt");

        try {
            FileUtils.writeStringToFile(digestOutputFile, digestHexString, Charset.defaultCharset());
        } catch (IOException e) {
            throw new EtapaDesafioException("An error occured while writing the digest hexstring to the file.", e);
        }
    }

    private static byte[] etapa2(SigningUtilities signingUtilities, byte[] fileBytes, byte[] pkcs12Bytes) throws EtapaDesafioException {
        SignerCertKey signerCertKey;
        try {
            signerCertKey = SigningUtilities.loadCertKeyFromPKCS12(pkcs12Bytes, keystoreCertAlias, privateKeyPassword.toCharArray());
        } catch (IOException e) {
            throw new EtapaDesafioException("Could not load keystore data. Check if the provided file is correct and if" +
                    "password is correct.", e);
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new EtapaDesafioException("An internal error occurred while loading the PKCS#12 keystore.", e);
        } catch (CertificateException e) {
            throw new EtapaDesafioException("The certificate of the provided keystore could not be loaded.", e);
        } catch (UnrecoverableKeyException e) {
            throw new EtapaDesafioException("The private key of the provided keystore could not be recovered. The password could be incorrect.", e);
        }

        X509Certificate signerCertificate = signerCertKey.getX509Certificate();
        PrivateKey signerKey = signerCertKey.getPrivateKey();
        byte[] signature;

        try {
            signature = signingUtilities.signData(fileBytes, signerKey, signerCertificate);
        } catch (OperatorCreationException e) {
            throw new EtapaDesafioException("Internal error during signature operation.", e);
        } catch (CertificateEncodingException e) {
            throw new EtapaDesafioException("An error occurred when trying encode the signing certificate. Verify if " +
                    "the certificate file is correct.", e);
        } catch (SigningException e) {
            throw new EtapaDesafioException("An error occurred while performing the signature.", e);
        }

        try {
            // Escrevendo a assinatura gerada no arquivo output/doc_signature.p7s
            File docSignatureFile = FileUtils.getFile("output/doc_signature.p7s");
            try (FileOutputStream docSignatureOutputStream = FileUtils.openOutputStream(docSignatureFile)) {
                docSignatureOutputStream.write(signature);
            } } catch (IOException e) {
            throw new EtapaDesafioException("An error occurred while writing to signature file output stream.", e);
        }

        return signature;
    }

    private static void etapa3(byte[] signature) throws EtapaDesafioException {
        try {
            boolean validSignature = SigningUtilities.verifySignature(signature);
            if (validSignature) {
                System.out.println("Etapa 3 result: true");
            } else {
                System.out.println("Etapa 3 result: false");
            }
        } catch (OperatorCreationException e) {
            throw new EtapaDesafioException("Internal error during signature operation.", e);
        } catch (CertificateException e) {
            throw new EtapaDesafioException("Certificate error. Verify if the certificate is correct.", e);
        } catch (IOException | CMSException e) {
            throw new EtapaDesafioException("An error occurred while processing the signed data. Verify if the data" +
                    "is correct", e);
        } catch (SignatureVerificationException e) {
            throw new EtapaDesafioException(e.getMessage(), e);
        }
    }

    private byte[] getResourceBytes(String resourceName) throws IOException {
        try (InputStream resourceStream = getClass().getClassLoader().getResourceAsStream(resourceName)) {
            if (resourceStream != null) {
                return resourceStream.readAllBytes();
            }
            throw new IOException(String.format("Could not read bytes from %s resource stream", resourceName));
        }
    }
}
