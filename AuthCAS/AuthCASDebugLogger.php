<?php
/**
 * Debug logger of the AuthCAS plugin.
 *
 * It writes to a dedicated file and is also usable as a logger by phpCAS (phpCAS only calls info()).
 * Tickets, passwords, cookies and the values of the CAS attributes are masked before being written.
 */
class AuthCASDebugLogger
{
    /** Above this size the file is moved to <file>.1 (replacing the previous one), so that debug mode left on cannot fill the disk */
    const MAX_SIZE = 5242880;

    /** A message longer than this is cut */
    const MAX_MESSAGE = 20000;

    /** @var string */
    private $file;

    /** @var boolean true once a write failed */
    private $failed = false;

    /**
     * @param string $file full path of the log file
     */
    public function __construct($file)
    {
        $this->file = $file;
    }

    /**
     * @return string
     */
    public function getFile()
    {
        return $this->file;
    }

    /**
     * @return boolean false if the file can not be written
     */
    public function isWritable()
    {
        return !$this->failed;
    }

    /**
     * Last lines of the log file (read from the end: the file may be several MB)
     * @param integer $maxLines
     * @return string|null null if there is no file or it can not be read
     */
    public function tail($maxLines = 300)
    {
        clearstatcache(true, $this->file);
        if (!is_file($this->file) || !is_readable($this->file)) {
            return null;
        }
        $size = (int) @filesize($this->file);
        $fh = @fopen($this->file, 'rb');
        if (!$fh) {
            return null;
        }
        $length = min($size, 262144);
        if ($length > 0) {
            fseek($fh, $size - $length);
            $content = (string) fread($fh, $length);
        } else {
            $content = '';
        }
        fclose($fh);
        $lines = explode("\n", rtrim($content, "\n"));
        if ($size > $length) {
            array_shift($lines); // first line is probably cut
        }
        return self::mask(implode("\n", array_slice($lines, -$maxLines)));
    }

    /**
     * Method used by phpCAS
     * @param string $message
     * @param array $context
     * @return void
     */
    public function info($message, array $context = array())
    {
        $this->write($message);
    }

    /**
     * @param string $message
     * @return void
     */
    public function write($message)
    {
        $message = (string) $message;
        if (strlen($message) > self::MAX_MESSAGE) {
            $message = substr($message, 0, self::MAX_MESSAGE) . ' [message cut]';
        }
        $message = self::mask($message);
        // no control character (terminal escape sequences), and the lines of a multi-line message are indented:
        // data coming from a request can not forge a line looking like a log entry
        $message = preg_replace('/[\x00-\x09\x0b-\x1f\x7f]/', '?', $message);
        $message = str_replace("\n", "\n    ", $message);
        $line = date('Y-m-d H:i:s') . ' [' . substr(md5((string) getmypid()), 0, 4) . '] ' . $message . "\n";

        clearstatcache(true, $this->file);
        if (is_file($this->file) && @filesize($this->file) > self::MAX_SIZE) {
            @rename($this->file, $this->file . '.1');
        }
        // the file is created readable by the web server user only
        $oldUmask = umask(0077);
        $result = @file_put_contents($this->file, $line, FILE_APPEND | LOCK_EX);
        umask($oldUmask);
        if ($result === false) {
            $this->failed = true;
        }
    }

    /**
     * Hide the values that must not be kept in a log file
     * @param string $message
     * @return string
     */
    public static function mask($message)
    {
        // CAS tickets (ST-, PT-, PGT-, PGTIOU-, TGT-...), in URLs and in XML answers
        $message = preg_replace('/\b((?:ST|PT|PGT|PGTIOU|TGT|LT)-)[A-Za-z0-9._\-]+/', '$1***', $message);
        $message = preg_replace('/(ticket(?:=|%3D))[^&\s"\'<]+/i', '$1***', $message);
        // password, session cookies and tokens
        $message = preg_replace('/\b((?:pass(?:word)?|pwd|PHPSESSID|LS-[A-Za-z0-9]+|YII_CSRF_TOKEN)[=:\s"\']+)[^&\s"\';<]+/i', '$1***', $message);
        // cookies traced by phpCAS: "Cookie Line: NAME=value; Path=/" and "NAME -> value"
        $message = preg_replace('/^(\s*Cookie Line:).*$/mi', '$1 ***', $message);
        $message = preg_replace('/^(\s*[\w.\-]+ -> ).*$/m', '$1***', $message);
        // values of the attributes traced by phpCAS: "* name=value" and print_r() dumps "[name] => value"
        $message = preg_replace('/^(\s*\* [^=\s]+=).*$/m', '$1***', $message);
        $message = preg_replace('/^(\s*\[[^\]]*\] => ).*$/m', '$1***', $message);
        // text of the XML elements of the CAS answer (attribute values, credentials), except the user name
        $message = preg_replace_callback('#<([\w.\-]+(?::[\w.\-]+)?)(\s[^>]*)?>([^<]+)</\1>#', function ($m) {
            if (strcasecmp($m[1], 'cas:user') === 0) {
                return $m[0];
            }
            return '<' . $m[1] . (isset($m[2]) ? $m[2] : '') . '>***</' . $m[1] . '>';
        }, $message);
        return $message;
    }
}
