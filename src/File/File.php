<?php
namespace CjsHttp\File;

use CjsHttp\File\Exception\FileException;
use CjsHttp\File\Exception\FileNotFoundException;
use CjsHttp\File\MimeType\MimeTypeGuesser;
use CjsHttp\File\MimeType\ExtensionGuesser;

class File extends \SplFileInfo
{
   
    public function __construct($path, $checkPath = true)
    {
        if ($checkPath && !is_file($path)) {
            throw new FileNotFoundException($path);
        }
        parent::__construct($path);
    }

    public function guessExtension()
    {
        $type = $this->getMimeType();
        $guesser = ExtensionGuesser::getInstance();

        return $guesser->guess($type);
    }

    public function getMimeType()
    {
        $guesser = MimeTypeGuesser::getInstance();

        return $guesser->guess($this->getPathname());
    }

    public function getExtension()
    {
        return pathinfo($this->getBasename(), PATHINFO_EXTENSION);
    }

    public function move($directory, $name = null)
    {
        $target = $this->getTargetFile($directory, $name);
        if (!@rename($this->getPathname(), $target)) {
            $error = error_get_last();
            throw new FileException(sprintf('Could not move the file "%s" to "%s" (%s)', $this->getPathname(), $target, strip_tags($error['message'])));
        }
        @chmod($target, 0666 & ~umask());
        return $target;
    }

    protected function getTargetFile($directory, $name = null)
    {
        if (!is_dir($directory)) {
            if (false === @mkdir($directory, 0777, true)) {
                throw new FileException(sprintf('Unable to create the "%s" directory', $directory));
            }
        } elseif (!is_writable($directory)) {
            throw new FileException(sprintf('Unable to write in the "%s" directory', $directory));
        }

        $target = rtrim($directory, '/\\').DIRECTORY_SEPARATOR.(null === $name ? $this->getBasename() : $this->getName($name));

        return new File($target, false);
    }
    
    protected function getName($name)
    {
        $originalName = str_replace('\\', '/', $name);
        $pos = strrpos($originalName, '/');
        $originalName = false === $pos ? $originalName : substr($originalName, $pos + 1);

        return $originalName;
    }
}
