<?php
namespace CjsHttp\File\MimeType;

use CjsHttp\File\Exception\FileNotFoundException;
use CjsHttp\File\Exception\AccessDeniedException;

class MimeTypeGuesser implements MimeTypeGuesserInterface
{
    private static $instance = null;

    protected $guessers = array();

    public static function getInstance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        if (FileBinaryMimeTypeGuesser::isSupported()) {
            $this->register(new FileBinaryMimeTypeGuesser());
        }

        if (FileinfoMimeTypeGuesser::isSupported()) {
            $this->register(new FileinfoMimeTypeGuesser());
        }
    }

    public function register(MimeTypeGuesserInterface $guesser)
    {
        array_unshift($this->guessers, $guesser);
    }

    public function guess($path)
    {
        if (!is_file($path)) {
            throw new FileNotFoundException($path);
        }

        if (!is_readable($path)) {
            throw new AccessDeniedException($path);
        }

        if (!$this->guessers) {
            $msg = 'Unable to guess the mime type as no guessers are available';
            if (!FileinfoMimeTypeGuesser::isSupported()) {
                $msg .= ' (Did you enable the php_fileinfo extension?)';
            }
            throw new \LogicException($msg);
        }

        foreach ($this->guessers as $guesser) {
            if (null !== $mimeType = $guesser->guess($path)) {
                return $mimeType;
            }
        }
    }
}
