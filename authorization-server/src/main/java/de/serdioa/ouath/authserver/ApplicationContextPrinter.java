package de.serdioa.ouath.authserver;

import java.util.Map;
import java.util.TreeMap;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.EventListener;


/**
 * Prints to the standard output beans available in the application context, after the context is started.
 */
public class ApplicationContextPrinter {

    @EventListener
    public void onApplicationStarted(ApplicationStartedEvent event) {
        ApplicationContext context = event.getApplicationContext();

        // Get all available beans, and put them in a TreeMap to sort alphabetically.
        Map<String, Object> beans = new TreeMap<>(BeanFactoryUtils.beansOfTypeIncludingAncestors(context, Object.class));

        System.out.println("Registered beans:");
        for (Map.Entry<String, Object> entry : beans.entrySet()) {
            System.out.printf("    %s -> %s%n", entry.getKey(), entry.getValue().getClass());
        }
        System.out.printf("Total %d registered beans%n", beans.size());
    }
}
