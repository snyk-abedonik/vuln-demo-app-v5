package demo;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.text.StringSubstitutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashMap;
import java.util.Map;

/**
 * Demo payment service.
 *
 * Deliberately calls into vulnerable code paths so Snyk reachability analysis
 * reports Reachability: function for Log4Shell (CVE-2021-44228) and
 * Text4Shell (CVE-2022-42889), and Reachability: package for the Commons
 * Collections gadget chain (CVE-2015-6420).
 */
public class PaymentService {

    // CVE-2021-44228 — Log4Shell
    // logger.info() with user-controlled input triggers the JNDI lookup path
    // inside log4j-core's MessagePatternConverter. Snyk marks this FUNCTION-reachable.
    private static final Logger logger = LogManager.getLogger(PaymentService.class);

    /**
     * Process a payment. The {@code orderId} value comes from the HTTP request
     * and is logged directly — the classic Log4Shell trigger pattern.
     */
    public void processPayment(String orderId, double amount) {
        logger.info("Processing payment for order: {}", orderId); // reachable: CVE-2021-44228
        logger.info("Amount: {}", amount);
    }

    /**
     * Format an order confirmation using commons-text StringSubstitutor.
     * Passing user input into replace() is the Text4Shell trigger pattern.
     * Snyk marks CVE-2022-42889 as FUNCTION-reachable.
     */
    public String formatConfirmation(String template, String orderId) {
        Map<String, String> values = new HashMap<>();
        values.put("orderId", orderId);
        return StringSubstitutor.replace(template, values); // reachable: CVE-2022-42889
    }

    /**
     * Deserialize a legacy transformer chain.
     * InvokerTransformer is the gadget entry point for CVE-2015-6420.
     * Snyk marks this PACKAGE-reachable (class is instantiated).
     */
    public Object applyTransformer(Object input) {
        Transformer transformer = new InvokerTransformer( // reachable: CVE-2015-6420
                "toString", new Class[]{}, new Object[]{});
        return transformer.transform(input);
    }
}
