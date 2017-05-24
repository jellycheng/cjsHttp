<?php
namespace CjsHttp\File\MimeType;

use CjsHttp\File\Exception\FileNotFoundException;
use CjsHttp\File\Exception\AccessDeniedException;

class FileinfoMimeTypeGuesser implements MimeTypeGuesserInterface
{
    private $magicFile;

    public function __construct($magicFile = null)
    {
        $this->magicFile = $magicFile;
    }

    public static function isSupported()
    {
        return function_exists('finfo_open');
    }

    /**
     * {@inheritdoc}
     */
    public function guess($path)
    {
        if (!is_file($path)) {
            throw new FileNotFoundException($path);
        }

        if (!is_readable($path)) {
            throw new AccessDeniedException($path);
        }

        if (!self::isSupported()) {
            return;
        }

        if (!$finfo = new \finfo(FILEINFO_MIME_TYPE, $this->magicFile)) {
            return;
        }

        return $finfo->file($path);
    }
}
