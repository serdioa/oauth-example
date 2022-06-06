package de.serdioa.ouath.authserver.jwt;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public class KeyStoreHolder {

    private final KeyStore keyStore;


    public KeyStoreHolder(String path, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        this.keyStore = KeyStore.getInstance(new File(path), password);
    }


    public KeyStoreHolder(String type, String provider, String path, char[] password)
            throws NoSuchProviderException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        this.keyStore = KeyStore.getInstance(type, provider);
        this.loadKeyStore(path, password);
    }


    private void loadKeyStore(String path, char[] password)
            throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        try ( FileInputStream fis = new FileInputStream(path);  BufferedInputStream bis = new BufferedInputStream(fis)) {
            this.keyStore.load(bis, password);
        }
    }


    public X509Certificate getCertificate(String alias) throws KeyStoreException {
        return (X509Certificate) this.keyStore.getCertificate(alias);
    }


    public KeyStore.PrivateKeyEntry getPrivateKeyEntry(String alias, char[] password)
            throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(password);
        return (KeyStore.PrivateKeyEntry) this.keyStore.getEntry(alias, protectionParameter);
    }


    public PrivateKey getPrivateKey(String alias, char[] password)
            throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        KeyStore.PrivateKeyEntry entry = this.getPrivateKeyEntry(alias, password);
        return entry.getPrivateKey();
    }
}
