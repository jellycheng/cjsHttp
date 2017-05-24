<?php
namespace CjsHttp\File\MimeType;

interface MimeTypeGuesserInterface
{
  
    public function guess($path);
}
