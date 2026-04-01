package org.keycloak.testsuite.pages;

import org.keycloak.testsuite.util.UIUtils;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

public class TrustedDeviceRegisterPage extends AbstractPage {

    @FindBy(id = "kc-trusted-device-yes")
    private WebElement trustButton;

    @FindBy(id = "kc-trusted-device-no")
    private WebElement rejectButton;

    @FindBy(id = "kc-trusted-device-name")
    private WebElement deviceName;

    @Override
    public boolean isCurrent() {
        return PageUtils.getPageTitle(driver).equals("Trust this device?");
    }

    public void confirmDevice() {
        UIUtils.clickLink(trustButton);
    }

    public void rejectDevice() {
        UIUtils.clickLink(rejectButton);
    }
}
