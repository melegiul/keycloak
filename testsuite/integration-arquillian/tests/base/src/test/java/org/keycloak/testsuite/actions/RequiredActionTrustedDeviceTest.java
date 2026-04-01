package org.keycloak.testsuite.actions;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Rule;
import org.junit.Test;

import org.keycloak.authentication.requiredactions.TrustedDeviceRegister;
import org.keycloak.cookie.CookieType;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.RealmModel;
import org.keycloak.models.credential.TrustedDeviceCredentialModel;
import org.keycloak.representations.TrustedDeviceToken;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RequiredActionProviderRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.pages.AppPage;

import org.keycloak.testsuite.pages.LoginPage;

import org.keycloak.testsuite.pages.RegisterPage;

import org.keycloak.testsuite.pages.TrustedDeviceRegisterPage;

import org.openqa.selenium.Cookie;

import java.util.LinkedList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class RequiredActionTrustedDeviceTest extends AbstractTestRealmKeycloakTest {
    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        RequiredActionProviderRepresentation requiredAction = new RequiredActionProviderRepresentation();
        requiredAction.setAlias(TrustedDeviceRegister.PROVIDER_ID);
        requiredAction.setProviderId(TrustedDeviceRegister.PROVIDER_ID);
        requiredAction.setName("Register Trusted Device");
        requiredAction.setEnabled(true);
        requiredAction.setDefaultAction(true);

        List<RequiredActionProviderRepresentation> requiredActions = new LinkedList<>();
        requiredActions.add(requiredAction);
        testRealm.setRequiredActions(requiredActions);
    }

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Page
    protected LoginPage loginPage;

    @Page
    protected RegisterPage registerPage;

    @Page
    protected TrustedDeviceRegisterPage trustDevicePage;

    @Page
    protected AppPage appPage;

    @Test
    public void setupTrustedDeviceRegister() {
        loginPage.open();
        loginPage.clickRegister();
        registerPage.register("firstName", "lastName", "email@mail.com", "setuptrusteddevice", "password", "password");

        String userId = events.expectRegister("setuptrusteddevice", "email@mail.com").assertEvent().getUserId();

        trustDevicePage.assertCurrent();

        trustDevicePage.confirmDevice();

        EventRepresentation updateCredentialEvent = events.expectRequiredAction(EventType.UPDATE_CREDENTIAL)
                .user(userId)
                .detail(Details.CREDENTIAL_TYPE, TrustedDeviceCredentialModel.TYPE)
                .detail(Details.USERNAME, "setuptrusteddevice").assertEvent();

        String authSessionId = updateCredentialEvent.getDetails().get(Details.CODE_ID);
        assertThat(appPage.getRequestType(), is(AppPage.RequestType.AUTH_RESPONSE));
        events.expectLogin().user(userId).session(authSessionId).detail(Details.USERNAME, "setuptrusteddevice").assertEvent();

        appPage.openAccount();
        Cookie trustedDeviceCookie = driver.manage().getCookieNamed(CookieType.TRUSTED_DEVICE.getName());
        assertThat("KEYCLOAK_TRUSTED_DEVICE cookie should be set", trustedDeviceCookie, notNullValue());

        testingClient.server().run(session -> {
            RealmModel realm = session.realms().getRealm(TEST_REALM_NAME);
            session.getContext().setRealm(realm);
            String tokenString = trustedDeviceCookie.getValue();
            assertThat("Token in cookie should be a set", tokenString, notNullValue());
            TrustedDeviceToken decoded = session.tokens().decode(tokenString, TrustedDeviceToken.class);
            assertThat("Token should be decoded successfully", decoded, notNullValue());
        });
    }

    @Test
    public void rejectTrustedDeviceRegister() {
        loginPage.open();
        loginPage.clickRegister();
        registerPage.register("firstName", "lastName", "email@mail.com", "rejecttrusteddevice", "password", "password");

        String userId = events.expectRegister("rejecttrusteddevice", "email@mail.com").assertEvent().getUserId();

        trustDevicePage.assertCurrent();

        trustDevicePage.rejectDevice();

        events.expectRequiredAction(EventType.UPDATE_CREDENTIAL_ERROR)
                .user(userId)
                .detail(Details.CREDENTIAL_TYPE, TrustedDeviceCredentialModel.TYPE)
                .detail(Details.REASON, "user_declined")
                .detail(Details.USERNAME, "rejecttrusteddevice").assertEvent();

        assertThat(appPage.getRequestType(), is(AppPage.RequestType.AUTH_RESPONSE));
        events.expectLogin().user(userId).detail(Details.USERNAME, "rejecttrusteddevice").assertEvent();

        appPage.openAccount();
        Cookie trustedDeviceCookie = driver.manage().getCookieNamed(CookieType.TRUSTED_DEVICE.getName());
        assertThat("KEYCLOAK_TRUSTED_DEVICE cookie should not be set", trustedDeviceCookie, nullValue());
    }
}
