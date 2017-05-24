<?php
namespace CjsHttp\File\MimeType;


interface ExtensionGuesserInterface
{
    public function guess($mimeType);
}
