<?php
/* Seed endpoint — this directory's .user.ini selects session.serialize_handler
 * = php_serialize, so the upload-progress key (which carries our payload after
 * a "|") is stored verbatim inside a php_serialize blob. */
echo "seed ok post=" . count($_POST) . "\n";
