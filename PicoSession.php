<?php

/**
 * Pico session plugin - cross-plugin session handling for Pico
 *
 * PicoSession ...
 *
 * @author  Daniel Rudolf
 * @link    http://picocms.org
 * @license http://opensource.org/licenses/MIT The MIT License
 * @version 1.0.0
 */
class PicoSession extends AbstractPicoPlugin
{
    protected $namespace;

    protected $plugins = array();
    protected $pluginsReadOnly = array();

    protected $sessionMeta;

    /**
     * @see PicoPluginInterface::__construct()
     */
    public function __construct(Pico $pico)
    {
        parent::__construct($pico);

        // load dependencies in non-composer environments
        if (!is_callable('random_bytes')) {
            if (file_exists(__DIR__ . '/vendor/paragonie/random_compat/lib/random.php')) {
                require(__DIR__ . '/vendor/paragonie/random_compat/lib/random.php');
            } else {
                throw new RuntimeException('Unable to load paragonie/random_compat');
            }
        }
    }

    public function onPluginsLoaded(array &$plugins)
    {
        // require >= Pico 2.0; Pico::VERSION wasn't defined before Pico 2.0
        if (!defined('Pico::VERSION')) {
            $this->setEnabled(false);
            return;
        }
    }

    public function onConfigLoaded(array &$config)
    {
        $defaultPluginConfig = array(
            'namespace' => '__PicoSession',
            'allowAutoStart' => false,
            'allowCommit' => true,
            'lifetime' => 21600,
            'timeout' => 7200,
            'secure' => null,
            'domain' => null,
            'path' => null
        );

        if (!isset($config['PicoSession']) || !is_array($config['PicoSession'])) {
            $config['PicoSession'] = $defaultPluginConfig;
            return;
        }

        $config['PicoSession'] += $defaultPluginConfig;

        if (!$config['PicoSession']['namespace']) {
            $config['PicoSession']['namespace'] = $defaultPluginConfig['namespace'];
        }
    }

    public function onRequestUrl(&$url)
    {
        $this->triggerEvent('onSessionInit', array($this, &$this->pluginsReadOnly, &$this->plugins));

        if (!$this->pluginsReadOnly && !$this->plugins) {
            // no plugin requested to start a session, so we don't start a session
            // this silently disables the plugin, but keeps dependant plugins enabled
            return;
        }

        $this->namespace = $this->getPluginConfig('namespace');
        $this->initSession();

        if (!$this->plugins && $this->getPluginConfig('allowCommit')) {
            // read-only session, don't lock session file
            session_write_close();
        }
    }

    protected function initSession()
    {
        // get session lifetime
        $lifetime = (int) $this->getPluginConfig('lifetime');

        // start session
        if (!$this->isActiveSession()) {
            // send session cookie
            if (ini_get('session.use_cookies')) {
                if (headers_sent($file, $line)) {
                    throw new RuntimeException(
                        'PicoSession failed to start session: Headers have already been sent '
                        . 'in "' . $file . '" on line ' . $line
                    );
                }

                $baseUrlComponents = parse_url($this->getBaseurl()) ?: array();

                $path = $this->getPluginConfig('path');
                if (!$path) {
                    $path = isset($baseUrlComponents['path']) ? rtrim($baseUrlComponents['path'], '/') . '/' : '/';
                }

                $domain = $this->getPluginConfig('domain');
                if (!$domain) {
                    $domain = isset($baseUrlComponents['host']) ? $baseUrlComponents['host'] : $_SERVER['HTTP_HOST'];
                }

                $secure = $this->getPluginConfig('secure');
                if ($secure === null) {
                    if (isset($baseUrlComponents['scheme'])) {
                        $secure = ($baseUrlComponents['scheme'] === 'https');
                    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
                        $secureProxyHeader = strtolower(current(explode(',', $_SERVER['HTTP_X_FORWARDED_PROTO'])));
                        $secure = in_array($secureProxyHeader, array('https', 'on', 'ssl', '1'));
                    } elseif (!empty($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] !== 'off')) {
                        $secure = true;
                    } elseif ($_SERVER['SERVER_PORT'] == 443) {
                        $secure = true;
                    } else {
                        $secure = false;
                    }
                }

                session_set_cookie_params($lifetime, $path, $domain, $secure, true);
            }

            // allow client caching by default; this might get overwritten by other plugins
            session_cache_limiter('private_no_expire');

            // start session in strict mode
            ini_set('session.use_strict_mode', 1);
            if (!session_start()) {
                throw new RuntimeException('PicoSession failed to start session');
            }
        } else {
            if (!$this->getPluginConfig('allowAutoStart')) {
                throw new RuntimeException('PicoSession failed to start session: Conflicting active session detected');
            }
        }

        if (!isset($_SESSION[$this->namespace . '__meta'])) {
            // new session
            // don't save session meta until we actually want to store some data
            $this->updateSessionMeta($lifetime);

            $this->triggerEvent('onSessionStart', array($this->sessionMeta));
        } else {
            $expire = array();

            $activeLifetime = (int) $_SESSION[$this->namespace . '__meta']['lifetime'];
            if ($activeLifetime) {
                $expire[] = $_SESSION[$this->namespace . '__meta']['created'] + $activeLifetime;
            }

            $timeout = (int) $this->getPluginConfig('timeout');
            if ($timeout) {
                $expire[] = $_SESSION[$this->namespace . '__meta']['updated'] + $timeout;
            }

            if ($expire && (time() >= min($expire))) {
                // invalidate expired session
                $this->invalidateSession($lifetime);
            } else {
                // use active session
                $_SESSION[$this->namespace . '__meta']['updated'] = time();
                $this->sessionMeta = $_SESSION[$this->namespace . '__meta'];

                $this->triggerEvent('onSessionResume', array($this->sessionMeta));
            }
        }
    }

    public function invalidateSession($lifetime = null)
    {
        unset($_SESSION[$this->namespace], $_SESSION[$this->namespace . '__meta']);
        $isMigrated = $this->migrateSession(true, $lifetime);

        $this->triggerEvent('onSessionReset', array($this->sessionMeta));

        return $isMigrated;
    }

    public function migrateSession($destroy = false, $lifetime = null)
    {
        if (!$this->isActiveSession()) {
            return false;
        }

        if ($lifetime !== null) {
            ini_set('session.cookie_lifetime', (int) $lifetime);
        }

        $isRegenerated = session_regenerate_id($destroy);

        if ($destroy) {
            $this->updateSessionMeta($lifetime);

            // lazy session initialization
            // only update session meta when the old session was already initialized
            if (isset($_SESSION[$this->namespace . '__meta'])) {
                $_SESSION[$this->namespace . '__meta'] = $this->sessionMeta;
            }
        }

        return $isRegenerated;
    }

    protected function updateSessionMeta($lifetime = null)
    {
        $this->sessionMeta = array(
            'created' => time(),
            'updated' => time(),
            'lifetime' => ($lifetime !== null) ? (int) $lifetime : (int) ini_get('session.cookie_lifetime')
        );
    }

    public function getSessionMeta()
    {
        return $this->sessionMeta;
    }

    public function isActiveSession()
    {
        return (PHP_VERSION_ID >= 50400) ? (session_status() === PHP_SESSION_ACTIVE) : (session_id() !== '');
    }

    public function has($pluginName, $name)
    {
        if ($this->namespace === null) {
            throw new LogicException('Cannot access a uninitialized session');
        }

        return isset($_SESSION[$this->namespace][$pluginName][$name]);
    }

    public function get($pluginName, $name)
    {
        return $this->has($pluginName, $name) ? $_SESSION[$this->namespace][$pluginName][$name] : null;
    }

    public function set($pluginName, $name, $value)
    {
        if (($this->namespace === null) || !$this->isActiveSession() || !isset($this->plugins[$pluginName])) {
            throw new LogicException('Cannot modify variables of a uninitialized, inactive or read-only session');
        }

        // lazy session initialization
        if (!isset($_SESSION[$this->namespace . '__meta'])) {
            $_SESSION[$this->namespace . '__meta'] = $this->sessionMeta;
        }

        $_SESSION[$this->namespace][$pluginName][$name] = $value;
    }

    public function remove($pluginName, $name)
    {
        if (($this->namespace === null) || !$this->isActiveSession() || !isset($this->plugins[$pluginName])) {
            throw new LogicException('Cannot modify variables of a uninitialized, inactive or read-only session');
        }

        unset($_SESSION[$this->namespace][$pluginName][$name]);
    }

    public function clear($pluginName)
    {
        if (($this->namespace === null) || !$this->isActiveSession() || !isset($this->plugins[$pluginName])) {
            throw new LogicException('Cannot modify variables of a uninitialized, inactive or read-only session');
        }

        unset($_SESSION[$this->namespace][$pluginName]);
    }

    public function close($pluginName)
    {
        if (isset($this->plugins[$pluginName])) {
            $this->pluginsReadOnly[$pluginName] = $this->plugins[$pluginName];
            unset($this->plugins[$pluginName]);

            if (!$this->plugins && $this->getPluginConfig('allowCommit')) {
                // write and close session file, releases lock
                session_write_close();
            }

            return true;
        }

        return false;
    }

    public function generateSignedToken($pluginName, $payload, $lifetime = null)
    {
        $secret = $this->get($pluginName, '__signedTokenSecret');
        if (!$secret) {
            $secret = self::generateRandomString(64);
            $this->set($pluginName, '__signedTokenSecret', $secret);
        }

        $lifetime = ($lifetime === null) ? (int) $this->getPluginConfig('lifetime') : (int) $lifetime;
        $expire = ($lifetime !== 0) ? time() + $lifetime : 0;
        $random = self::generateRandomString(8);

        $hash = hash_hmac('sha256', $payload . '-' . $random . '-' . $expire, $secret);
        return array('hash' => $hash, 'random' => $random, 'expire' => $expire);
    }

    public function verifySignedToken($pluginName, $payload, $token)
    {
        $hash = isset($token['hash']) ? (string) $token['hash'] : '';
        $expire = isset($token['expire']) ? (int) $token['expire'] : 0;
        $random = isset($token['random']) ? (string) $token['random'] : '';

        if (!$hash || !$random || ($expire && (time() > $expire))) {
            return false;
        }

        $secret = $this->get($pluginName, '__signedTokenSecret');
        $expectedHash = hash_hmac('sha256', $payload . '-' . $random . '-' . $expire, $secret);

        return self::secureCompare($expectedHash, $hash);
    }

    public static function generateRandomString($bytes)
    {
        // built-in function in PHP 7.0+,
        // fallback to paragonie/random_compat otherwise
        return bin2hex(random_bytes($bytes));
    }

    public static function secureCompare($string1, $string2)
    {
        if (!is_string($string1) || !$string1 || !is_string($string2) || !$string2) {
            return false;
        }

        $length = 0;
        if (function_exists('mb_strlen')) {
            $length = mb_strlen($string1, '8bit');
            if ($length !== mb_strlen($string2, '8bit')) {
                return false;
            }
        } else {
            $length = strlen($string1);
            if ($length !== strlen($string2)) {
                return false;
            }
        }

        $result = 0;
        for ($i = 0; $i < $length; $i++) {
            $result |= ord($string2[$i]) ^ ord($string1[$i]);
        }

        return ($result === 0);
    }
}
