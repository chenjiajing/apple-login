<?php

namespace ChenJiaJing\AppleLogin;

use ChenJiaJing\AppleLogin\Lib\JWK;
use ChenJiaJing\AppleLogin\Lib\JWT;
use Mockery\Exception;

class AppleLogin extends LoginBase
{
  protected $_instance;

  public function __construct(string $identityToken)
  {
    $instance = self::decodeIdentityToken($identityToken);
    if (is_null($instance)) {
      throw new Exception('AppleLogin received null instance.');
    }
    $this->_instance = $instance;
  }

  public function __call($method, $args)
  {
    return call_user_func_array(array($this->_instance, $method), $args);
  }

  public function __get($key)
  {
    return (isset($this->_instance->$key)) ? $this->_instance->$key : null;
  }

  public function __set($key, $val)
  {
    return $this->_instance->$key = $val;
  }

  public function getEmail(): ?string
  {
    return (isset($this->_instance->email)) ? $this->_instance->email : null;
  }

  public function getUser(): ?string
  {
    return (isset($this->_instance->sub)) ? $this->_instance->sub : null;
  }

  public function verifyUser(string $user): bool
  {
    return $user === $this->getUser();
  }
}
