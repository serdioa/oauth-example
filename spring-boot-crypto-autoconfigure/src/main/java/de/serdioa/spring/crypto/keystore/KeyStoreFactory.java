package de.serdioa.spring.crypto.keystore;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.util.Assert;


/**
 * Spring {@link FactoryBean} for creating a {@link KeyStore}.
 */
@Getter
@Setter
public class KeyStoreFactory implements FactoryBean<KeyStore> {

    private static final Logger logger = LoggerFactory.getLogger(KeyStoreFactory.class);

    /**
     * Default keystore type is {@code JKS}, i.e. the keystore type commonly used before Java 9.
     */
    public static final String DEFAULT_TYPE = "JKS";

    /**
     * Default keystore provider is {@code SUN}, i.e. the keystore provider build-in in JDK.
     */
    public static final String DEFAULT_PROVIDER = "SUN";

    // The type of the keystore, defaults to "JKS", i.e. the keystore type commonly used before Java 9.
    private String type = DEFAULT_TYPE;

    // The keystore provider to be used to load the keystore, defaults to "SUN", i.e. the keystore provider build-in
    // in JDK.
    private String provider = DEFAULT_PROVIDER;

    // The URL of the keystore. Either the URL or the path shall be provided, but not both.
    private URL url;

    // The path to the keystore. Either the URL or the path shall be provided, but not both.
    private String path;

    // The password of the keystore.
    private char[] password;

    // The instantiated and loaded keystore.
    private KeyStore keystore;


    @PostConstruct
    public void afterPropertiesSet() throws BeanInitializationException {
        Assert.notNull(this.type, "type is required");
        Assert.notNull(this.provider, "provider is required");
        Assert.notNull(this.password, "password is required");

        // One of url or path shall be specified, but not both.
        Assert.isTrue(this.url != null || this.path != null, "either url or path is required");
        Assert.isTrue(this.url == null || this.path == null, "either url or path is required, but not both");

        try {
            // Instantiate and load the keystore.
            this.keystore = KeyStore.getInstance(this.type, this.provider);
            this.loadKeystore();
        } catch (IOException | KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException ex) {
            throw new BeanInitializationException("Exception when initilizing keystore '" + this.path + "'"
                    + "with keystore type '" + this.type + "', provider '" + this.provider + "'", ex);
        } finally {
            // Purge the password, to not keep it in memory longer than necessary.
            this.purgePassword();
        }
    }


    private void loadKeystore() throws IOException, NoSuchAlgorithmException, CertificateException {
        if (this.url != null) {
            this.loadKeystoreFromUrl();
        } else {
            this.loadKeystoreFromPath();
        }
    }


    private void loadKeystoreFromUrl() throws IOException, NoSuchAlgorithmException, CertificateException {
        logger.debug("Loading keystore (type {}, provider {}) from URL '{}'", this.type, this.provider, this.url);

        try ( InputStream is = this.url.openStream()) {
            this.loadKeystore(is);
        }
    }


    private void loadKeystoreFromPath() throws IOException, NoSuchAlgorithmException, CertificateException {
        logger.debug("Loading keystore (type {}, provider {}) from file '{}'", this.type, this.provider, this.path);

        try ( InputStream is = new FileInputStream(this.path)) {
            this.loadKeystore(is);
        }
    }


    private void loadKeystore(InputStream is) throws IOException, NoSuchAlgorithmException, CertificateException {
        try ( BufferedInputStream bis = new BufferedInputStream(is)) {
            this.keystore.load(bis, this.password);
        }
    }


    private void purgePassword() {
        Arrays.fill(this.password, (char) 0);
    }


    @Override
    public KeyStore getObject() throws Exception {
        return this.keystore;
    }


    @Override
    public Class<?> getObjectType() {
        return KeyStore.class;
    }
}
