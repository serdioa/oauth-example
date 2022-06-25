package de.serdioa.boot.autoconfigure.crypto;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


/**
 * Spring-Boot autoconfiguration to register BouncyCastle security provider, if it is available in the classpath.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(BouncyCastleProvider.class)
public class BouncyCastleProviderAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(BouncyCastleProviderAutoConfiguration.class);


    @Bean
    public BeanFactoryPostProcessor bouncyCastleProviderRegistrator() {
        return new BeanFactoryPostProcessor() {
            @Override
            public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
                if (!this.isBouncyCastleProviderRegistered()) {
                    this.registerBouncyCastleProvider();
                }
            }


            private boolean isBouncyCastleProviderRegistered() {
                for (Provider provider : Security.getProviders()) {
                    if (provider instanceof BouncyCastleProvider) {
                        logger.info("BouncyCastle security provider {}-{} is already registered",
                                provider.getName(), provider.getVersionStr());
                        return true;
                    }
                }

                return false;
            }


            private void registerBouncyCastleProvider() {
                logger.info("Registering BouncyCastle security provider");

                BouncyCastleProvider provider = new BouncyCastleProvider();
                Security.addProvider(provider);

                logger.info("Registered BouncyCastle security provider {}-{}",
                        provider.getName(), provider.getVersionStr());
            }
        };
    }
}
