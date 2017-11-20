<?php

namespace Krenor\LdapAuth;

use App\User;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Krenor\LdapAuth\Exceptions\EmptySearchResultException;
use Krenor\LdapAuth\Objects\Ldap;

class LdapAuthUserProvider implements UserProvider
{
    /**
     * LDAP Wrapper.
     *
     * @var Ldap
     */
    protected $ldap;

    /**
     * LDAP Auth User Class.
     *
     * @var string
     */
    protected $model;

    /**
     * @param Ldap $ldap
     * @param string $model
     */
    public function __construct(Ldap $ldap, $model)
    {
        $this->ldap = $ldap;
        $this->model = $model;
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        return $this->retrieveByCredentials(
            ['email' => $identifier]
        );
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed $identifier
     * @param  string $token
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByToken($identifier, $token)
    {
        // this shouldn't be needed as user / password is in ldap
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user
     * @param  string $token
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        // this shouldn't be needed as user / password is in ldap
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array $credentials
     * @return Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
//        $username = $credentials[config('ldap.auth_identifier_name')];
        $username = $credentials['email'];

        // If the user is identified by his ID
        if (is_int($username)) {
            return User::find($username) ?: null;
        }

        // Else: LDAP query
        try {
            $result = $this->ldap->find($username);

            if (!is_null($result)) {
                $ldapMapping = array_replace([
                    'name' => 'name',
                    'email' => 'email',
                ], $this->getLdapMapping());
                $user = User::where('email', $username)->first();
                if (!($user instanceof User)) {
                    $user = new User();
                    $user->email = $username;
                    $user->admin = 0;
                }
                $user->name = $result[$ldapMapping['name']][0];
                $user->password = $result['dn'];
                $user->active = 1;
                $user->save();
                return $user;
            }
        } catch (EmptySearchResultException $e) {
            // Do nothing
        }

        return null;
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user
     * @param  array $credentials
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        return $this->ldap->auth(
            $user->password,
            $credentials['password']
        );
    }

    /**
     * Return the active LDAP property mapping
     *
     * @return array LDAP property mapping
     */
    protected function getLdapMapping()
    {
        $ldapMapping = [];
        foreach (array_filter(array_map('trim', explode(',', env('LDAP_MAPPING')))) as $mapping) {
            $mapping = explode('=', $mapping);
            if (count($mapping) == 2) {
                $ldapMapping[trim($mapping[0])] = trim($mapping[1]);
            }
        }
        return $ldapMapping;
    }
}
