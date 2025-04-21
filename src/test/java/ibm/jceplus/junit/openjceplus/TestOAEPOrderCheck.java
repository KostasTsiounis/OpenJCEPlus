package ibm.jceplus.junit.openjceplus;

import ibm.jceplus.junit.base.BaseTestOAEPOrderCheck;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public class TestOAEPOrderCheck extends BaseTestOAEPOrderCheck {

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }
}