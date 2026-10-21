<?php
/* Trigger endpoint — stand-in for any application page that calls
 * session_start() with its classes already loaded. The default `php` handler
 * splits the seeded blob at the FIRST "|" and unserializes our object; the
 * decode failure then runs its __destruct inside session_start(). */
class Logger {
    public $cmd = "";
    function __destruct() { echo "[gadget] "; system($this->cmd); echo "\n"; }
}
session_start();
echo "[api] session started\n";
