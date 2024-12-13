<?php

/**
 * Piwik - free/libre analytics platform
 *
 * @link http://piwik.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 */

namespace Piwik\Plugins\LoginOIDC;

use Exception;
use Piwik\Access;
use Piwik\Auth;
use Piwik\Common;
use Piwik\Config;
use Piwik\Container\StaticContainer;
use Piwik\Db;
use Piwik\Nonce;
use Piwik\Piwik;
use Piwik\Plugins\UsersManager\API as UsersManagerAPI;
use Piwik\Plugins\UsersManager\Model;
use Piwik\Request;
use Piwik\Session\SessionFingerprint;
use Piwik\Session\SessionInitializer;
use Piwik\Url;
use Piwik\View;

class Controller extends \Piwik\Plugin\Controller
{
    /**
     * Name of the none used in forms by this plugin.
     *
     * @var string
     */
    const OIDC_NONCE = "LoginOIDC.nonce";

    /**
     * Auth implementation to login users.
     * https://developer.matomo.org/api-reference/Piwik/Auth
     *
     * @var Auth
     */
    protected $auth;

    /**
     * Initializes authenticated sessions.
     *
     * @var SessionInitializer
     */
    protected $sessionInitializer;

    /**
     * Revalidates user authentication.
     *
     * @var PasswordVerifier
     */
    protected $passwordVerify;

    /**
     * Constructor.
     *
     * @param Auth                $auth
     * @param SessionInitializer  $sessionInitializer
     */
    public function __construct(Auth $auth = null, SessionInitializer $sessionInitializer = null)
    {
        parent::__construct();

        if (empty($auth)) {
            $auth = StaticContainer::get("Piwik\Plugins\LoginOIDC\Auth");
        }
        $this->auth = $auth;

        if (empty($sessionInitializer)) {
            $sessionInitializer = new SessionInitializer();
        }
        $this->sessionInitializer = $sessionInitializer;

        if (empty($passwordVerify)) {
            $passwordVerify = StaticContainer::get("Piwik\Plugins\Login\PasswordVerifier");
        }
        $this->passwordVerify = $passwordVerify;
    }

    /**
     * Render the custom user settings layout.
     *
     * @return string
     */
    public function userSettings() : string
    {
        $providerUser = $this->getProviderUser("oidc");
        return $this->renderTemplate("userSettings", array(
            "isLinked" => !empty($providerUser),
            "remoteUserId" => $providerUser["provider_user"],
            "nonce" => Nonce::getNonce(self::OIDC_NONCE)
        ));
    }

    /**
     * Render the oauth login button.
     *
     * @return string
     */
    public function loginMod() : string
    {
        $settings = new \Piwik\Plugins\LoginOIDC\SystemSettings();
        return $this->renderTemplate("loginMod", array(
            "caption" => $settings->authenticationName->getValue(),
            "nonce" => Nonce::getNonce(self::OIDC_NONCE)
        ));
    }

    /**
     * Render the oauth login button when current user is linked to a remote user.
     *
     * @return string|null
     */
    public function confirmPasswordMod() : ?string
    {
        $providerUser = $this->getProviderUser("oidc");
        return empty($providerUser) ? null : $this->loginMod();
    }

    /**
     * Remove link between the currently signed user and the remote user.
     *
     * @return void
     */
    public function unlink()
    {
        if ($_SERVER["REQUEST_METHOD"] !== "POST") {
            throw new Exception(Piwik::translate("LoginOIDC_MethodNotAllowed"));
        }
        // csrf protection
        Nonce::checkNonce(self::OIDC_NONCE, $_POST["form_nonce"]);

        $sql = "DELETE FROM " . Common::prefixTable("loginoidc_provider") . " WHERE user=? AND provider=?";
        $bind = array(Piwik::getCurrentUserLogin(), "oidc");
        Db::query($sql, $bind);
        $this->redirectToIndex("UsersManager", "userSecurity");
    }

    /**
     * Redirect to the authorize url of the remote oauth service.
     *
     * @return void
     */
    public function signin()
    {
        $settings = new \Piwik\Plugins\LoginOIDC\SystemSettings();

        $allowedMethods = array("POST");
        if (!$settings->disableDirectLoginUrl->getValue()) {
            array_push($allowedMethods, "GET");
        }
        if (!in_array($_SERVER["REQUEST_METHOD"], $allowedMethods)) {
            throw new Exception(Piwik::translate("LoginOIDC_MethodNotAllowed"));
        }

        if ($_SERVER["REQUEST_METHOD"] === "POST") {
            // csrf protection
            Nonce::checkNonce(self::OIDC_NONCE, $_POST["form_nonce"]);
        }

        if (!$this->isPluginSetup($settings)) {
            throw new Exception(Piwik::translate("LoginOIDC_ExceptionNotConfigured"));
        }

        $_SESSION["loginoidc_state"] = $this->generateKey(32);
        $params = array(
            "client_id" => $settings->clientId->getValue(),
            "scope" => $settings->scope->getValue(),
            "redirect_uri"=> $this->getRedirectUri(),
            "state" => $_SESSION["loginoidc_state"],
            "response_type" => "code"
        );
        $url = $settings->authorizeUrl->getValue();
        $url .= (parse_url($url, PHP_URL_QUERY) ? "&" : "?") . http_build_query($params);
        Url::redirectToUrl($url);
    }

    /**
     * Handle callback from oauth service.
     * Verify callback code, exchange for authorization token and fetch userinfo.
     *
     * @return void
     */
    public function callback()
    {
        error_log("LoginOIDC: Starting callback process...");

        $settings = new \Piwik\Plugins\LoginOIDC\SystemSettings();
        if (!$this->isPluginSetup($settings)) {
            error_log("LoginOIDC: Plugin is not configured properly.");
            throw new Exception(Piwik::translate("LoginOIDC_ExceptionNotConfigured"));
        }

        // Validate state parameter
        if ($_SESSION["loginoidc_state"] !== Request::fromGet()->getStringParameter("state")) {
            error_log("LoginOIDC: State mismatch error during OIDC callback.");
            throw new Exception(Piwik::translate("LoginOIDC_ExceptionStateMismatch"));
        }
        unset($_SESSION["loginoidc_state"]);

        $provider = Request::fromGet()->getStringParameter("provider");
        if ($provider !== "oidc") {
            error_log("LoginOIDC: Unknown provider received: $provider");
            throw new Exception(Piwik::translate("LoginOIDC_ExceptionUnknownProvider"));
        }

        // Exchange authorization code for tokens
        $data = [
            "client_id" => $settings->clientId->getValue(),
            "client_secret" => $settings->clientSecret->getValue(),
            "code" => Request::fromGet()->getStringParameter("code"),
            "redirect_uri" => $this->getRedirectUri(),
            "grant_type" => "authorization_code",
            "state" => Request::fromGet()->getStringParameter("state"),
        ];
        $dataString = http_build_query($data);

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $dataString);
        curl_setopt($curl, CURLOPT_HTTPHEADER, [
            "Content-Type: application/x-www-form-urlencoded",
            "Accept: application/json",
            "User-Agent: LoginOIDC-Matomo-Plugin",
        ]);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_URL, $settings->tokenUrl->getValue());
        $response = curl_exec($curl);
        curl_close($curl);
        $result = json_decode($response);

        if (empty($result) || empty($result->access_token)) {
            error_log("LoginOIDC: Failed to retrieve access token.");
            throw new Exception(Piwik::translate("LoginOIDC_ExceptionInvalidResponse"));
        }

        $_SESSION['loginoidc_idtoken'] = empty($result->id_token) ? null : $result->id_token;
        $_SESSION['loginoidc_auth'] = true;

        // Fetch user info using the access token
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_HTTPHEADER, [
            "Authorization: Bearer " . $result->access_token,
            "Accept: application/json",
            "User-Agent: LoginOIDC-Matomo-Plugin",
        ]);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_URL, $settings->userinfoUrl->getValue());
        $response = curl_exec($curl);
        curl_close($curl);
        $result = json_decode($response);

        // Get the username or user ID from Keycloak
        $userinfoId = $settings->userinfoId->getValue();
        $username = $result->$userinfoId;

        if (empty($username)) {
            error_log("LoginOIDC: Missing user identifier in Keycloak response.");
            throw new Exception(Piwik::translate("LoginOIDC_ExceptionInvalidResponse"));
        }

        // Extract roles from Keycloak claims
        $roles = isset($result->dot_jenkins_bot_authorisation) ? $result->dot_jenkins_bot_authorisation : [];
        $role = $this->mapRolesToMatomoRole($roles);

        // Log roles for debugging
        error_log("LoginOIDC: Username: $username");
        error_log("LoginOIDC: Keycloak roles: " . json_encode($roles));
        error_log("LoginOIDC: Mapped Matomo role: $role");

        // Add or update role in Matomo
        try {
            $this->addRoleWithPermissions($username, $role);
        } catch (Exception $e) {
            error_log("LoginOIDC: Failed to update Matomo role for user $username. Error: " . $e->getMessage());
            throw $e;
        }

        // Check if the user exists in Matomo
        $user = $this->getUserByRemoteId("oidc", $username);

        if (empty($user)) {
            if (Piwik::isUserIsAnonymous()) {
                // New user signup
                $email = isset($result->email) ? $result->email : $username . "@example.com";
                error_log("LoginOIDC: Signing up new user $username with role $role.");
                $this->signupUser($settings, $username, $email, $role);
            } else {
                // Link account for signed-in user
                error_log("LoginOIDC: Linking existing account to user $username.");
                $this->linkAccount($username, null, $role);
                $this->redirectToIndex("UsersManager", "userSecurity");
            }
        } else {
            if (Piwik::isUserIsAnonymous()) {
                // Sign in existing user
                error_log("LoginOIDC: Signing in existing user $username.");
                $this->signinAndRedirect($user, $settings);
            } else {
                if (Piwik::getCurrentUserLogin() === $user["login"]) {
                    error_log("LoginOIDC: User $username is already signed in.");
                    $this->passwordVerify->setPasswordVerifiedCorrectly();
                    return;
                } else {
                    error_log("LoginOIDC: User $username is linked to a different account.");
                    throw new Exception(Piwik::translate("LoginOIDC_ExceptionAlreadyLinkedToDifferentAccount"));
                }
            }
        }
    }


    /**
     * Fetch user role from external JSON source.
     *
     * @param string $username
     * @return string
     */
    private function getRoleFromExternalSource(string $username): string
    {
        $jsonString = file_get_contents('/path/to/external/roles.json'); // Path to your JSON file
        $data = json_decode($jsonString, true);

        if (!isset($data['users'])) {
            error_log("No users found in JSON");
            return 'reader'; // Default to 'reader' role
        }

        foreach ($data['users'] as $user) {
            if (strtolower($user['username']) === strtolower($username)) {
                return strtolower($user['role']); // Return role from JSON
            }
        }

        error_log("No role found for user {$username}. Defaulting to 'reader'.");
        return 'reader'; // Default role if user not found
    }



    /**
     * Check whether the given user has superuser access.
     * The function in Piwik\Core cannot be used because it requires an admin user being signed in.
     * It was used as a template for this function.
     * See: {@link \Piwik\Core::hasTheUserSuperUserAccess($theUser)} method.
     * See: {@link \Piwik\Plugins\UsersManager\Model::getUsersHavingSuperUserAccess()} method.
     * 
     * @param  string  $theUser A username to be checked for superuser access
     * @return bool
     */
    private function hasTheUserSuperUserAccess(string $theUser)
    {
        $userModel = new Model();
        $superUsers = $userModel->getUsersHavingSuperUserAccess();

        foreach ($superUsers as $superUser) {
            if ($theUser === $superUser['login']) {
                return true;
            }
        }

        return false;
    }

    /**
     * Create a link between the remote user and the currently signed in user.
     *
     * @param  string  $providerUserId
     * @param  string  $matomoUserLogin Override the local user if non-null
     * @return void
     */
    private function linkAccount(string $providerUserId, string $matomoUserLogin = null, string $role = null)
    {
        if ($matomoUserLogin === null) {
            $matomoUserLogin = Piwik::getCurrentUserLogin();
        }
    
        $sql = "INSERT INTO " . Common::prefixTable("loginoidc_provider") . " (user, provider_user, provider, date_connected) VALUES (?, ?, ?, ?)";
        $bind = array($matomoUserLogin, $providerUserId, "oidc", date("Y-m-d H:i:s"));
        Db::query($sql, $bind);
    
        if ($role !== null) {
            $this->addRoleWithPermissions($matomoUserLogin, $role);
        }
    }

    // private function addRoleWithPermissions(string $username, string $role)
    // {
    //     // Map OIDC roles to Matomo access roles
    //     $permissionsMap = [
    //         'administrator' => 'admin',
    //         'editor' => 'write',
    //         'reader' => 'view',
    //     ];
    
    //     $role = strtolower($role);
    //     if (!isset($permissionsMap[$role])) {
    //         throw new Exception("Invalid role: $role");
    //     }
    
    //     $matomoRole = $permissionsMap[$role];
    
    //     // Log role assignment
    //     error_log("Assigning Matomo role: $matomoRole for user: $username");
    
    //     // Insert or update the user's access in the matomo_access table
    //     $sql = "INSERT INTO " . Common::prefixTable("access") . " (login, idsite, access)
    //             VALUES (?, ?, ?)
    //             ON DUPLICATE KEY UPDATE access = VALUES(access)";
        
    //     // Assume idsite is 1 for the current site (adjust as needed)
    //     $idsite = 1;
    
    //     try {
    //         Db::query($sql, [$username, $idsite, $matomoRole]);
    //         error_log("Role assigned successfully for user: $username with access: $matomoRole");
    //     } catch (Exception $e) {
    //         error_log("Failed to assign role for user: $username. Error: " . $e->getMessage());
    //         throw $e;
    //     }
    // }

    private function addRoleWithPermissions(string $username, string $role)
    {
        $permissionsMap = [
            'administrator' => 'admin',
            'editor' => 'write',
            'reader' => 'view',
        ];
    
        $role = strtolower($role);
        if (!isset($permissionsMap[$role])) {
            throw new Exception("Invalid role: $role");
        }
    
        $matomoRole = $permissionsMap[$role];
        $idsite = 1; // Adjust if dynamic site ID is required
    
        // Log the role mapping
        error_log("Mapping role for user $username: OIDC Role - $role, Matomo Role - $matomoRole");
    
        // Insert or update the matomo_access table
        $sql = "INSERT INTO " . Common::prefixTable("access") . " (login, idsite, access)
                VALUES (?, ?, ?)
                ON DUPLICATE KEY UPDATE access = VALUES(access)";
        
        try {
            Db::query($sql, [$username, $idsite, $matomoRole]);
            error_log("Role assigned successfully for user: $username with access: $matomoRole");
        } catch (Exception $e) {
            error_log("Failed to assign role for user: $username. Error: " . $e->getMessage());
            throw $e;
        }
    }
    
    

    /**
     * Determine if all the required settings have been setup.
     *
     * @param  SystemSettings  $settings
     * @return bool
     */
    private function isPluginSetup($settings) : bool
    {
        return !empty($settings->authorizeUrl->getValue())
            && !empty($settings->tokenUrl->getValue())
            && !empty($settings->userinfoUrl->getValue())
            && !empty($settings->clientId->getValue())
            && !empty($settings->clientSecret->getValue());
    }

    /**
     * Sign up a new user and link him with a given remote user id.
     *
     * @param  SystemSettings  $settings
     * @param  string          $providerUserId   Remote user id
     * @param  string          $matomoUserLogin  Users email address, will be used as username as well
     * @return void
     */
    private function signupUser($settings, string $providerUserId, string $matomoUserLogin = null, string $role = null)
    {
        if ($settings->allowSignup->getValue()) {
            if (empty($matomoUserLogin)) {
                throw new Exception(Piwik::translate("LoginOIDC_ExceptionUserNotFoundAndNoEmail"));
            }

            Access::getInstance()->doAsSuperUser(function () use ($matomoUserLogin) {
                UsersManagerApi::getInstance()->addUser(
                    $matomoUserLogin,
                    "(disallow password login)",
                    $matomoUserLogin,
                    true
                );
            });

            $userModel = new Model();
            $user = $userModel->getUser($matomoUserLogin);
            $this->linkAccount($providerUserId, $matomoUserLogin, $role);
            $this->signinAndRedirect($user, $settings);
        } else {
            throw new Exception(Piwik::translate("LoginOIDC_ExceptionUserNotFoundAndSignupDisabled"));
        }
    }


    /**
     * Sign in the given user and redirect to the front page.
     *
     * @param  array  $user
     * @return void
     */
    private function signinAndRedirect(array $user, SystemSettings $settings)
    {
        $this->auth->setLogin($user["login"]);
        $this->auth->setForceLogin(true);
        $this->sessionInitializer->initSession($this->auth);
        if ($settings->bypassTwoFa->getValue()) {
            $sessionFingerprint = new SessionFingerprint();
            $sessionFingerprint->setTwoFactorAuthenticationVerified();
        }
        Url::redirectToUrl("index.php");
    }

    /**
     * Generate cryptographically secure random string.
     *
     * @param  int    $length
     * @return string
     */
    private function generateKey(int $length = 64) : string
    {
        // thanks ccbsschucko at gmail dot com
        // http://docs.php.net/manual/pl/function.random-bytes.php#122766
        $length = ($length < 4) ? 4 : $length;
        return bin2hex(random_bytes(($length - ($length % 2)) / 2));
    }

    /**
     * Generate the redirect url on which the oauth service has to redirect.
     *
     * @return string
     */
    private function getRedirectUri() : string
    {
        $settings = new \Piwik\Plugins\LoginOIDC\SystemSettings();

        if (!empty($settings->redirectUriOverride->getValue())) {
            return $settings->redirectUriOverride->getValue();
        } else {
            $params = array(
                "module" => "LoginOIDC",
                "action" => "callback",
                "provider" => "oidc"
            );
            return Url::getCurrentUrlWithoutQueryString() . "?" . http_build_query($params);
        }
    }

    /**
     * Fetch user from database given the provider and remote user id.
     *
     * @param  string  $provider
     * @param  string  $remoteId
     * @return array
     */
    private function getUserByRemoteId($provider, $remoteId)
    {
        $sql = "SELECT user FROM " . Common::prefixTable("loginoidc_provider") . " WHERE provider=? AND provider_user=?";
        $result = Db::fetchRow($sql, array($provider, $remoteId));
        if (empty($result)) {
            return $result;
        } else {
            $userModel = new Model();
            return $userModel->getUser($result["user"]);
        }
    }

    /**
     * Fetch provider information for the currently signed in user.
     *
     * @param  string  $provider
     * @return array
     */
    private function getProviderUser($provider)
    {
        $sql = "SELECT user, provider_user, provider FROM " . Common::prefixTable("loginoidc_provider") . " WHERE provider=? AND user=?";
        return Db::fetchRow($sql, array($provider, Piwik::getCurrentUserLogin()));
    }

}
