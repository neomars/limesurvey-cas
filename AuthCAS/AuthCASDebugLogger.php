<?php
/**
 * Debug logger of the AuthCAS plugin.
 *
 * It writes to a dedicated file and is also usable as a logger by phpCAS (phpCAS only calls info()).
 * Tickets, passwords and session identifiers are masked before being written.
 */
class AuthCASDebugLogger
{
    /** Above this size the file is emptied, so that debug mode left on cannot fill the disk */
    const MAX_SIZE = 5242880;

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
        $message = self::mask((string) $message);
        $line = date('Y-m-d H:i:s') . ' [' . substr(md5((string) getmypid()), 0, 4) . '] ' . $message . "\n";
        $flags = FILE_APPEND | LOCK_EX;
        clearstatcache(true, $this->file);
        if (is_file($this->file) && @filesize($this->file) > self::MAX_SIZE) {
            $flags = LOCK_EX;
            $line = date('Y-m-d H:i:s') . " [log truncated: size limit reached]\n" . $line;
        }
        $isNew = !is_file($this->file);
        if (@file_put_contents($this->file, $line, $flags) === false) {
            $this->failed = true;
            return;
        }
        if ($isNew) {
            @chmod($this->file, 0600);
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
        $message = preg_replace('/(ticket=)[^&\s"\'<]+/i', '$1***', $message);
        // password, session cookies and tokens
        $message = preg_replace('/\b((?:pass(?:word)?|pwd|PHPSESSID|LS-[A-Za-z0-9]+|YII_CSRF_TOKEN)[=:\s"\']+)[^&\s"\';<]+/i', '$1***', $message);
        return $message;
    }
}
