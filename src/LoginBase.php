<?php

namespace ChenJiaJing\AppleLogin;
use ChenJiaJing\AppleLogin\Lib\JWK;
use ChenJiaJing\AppleLogin\Lib\JWT;
use Mockery\Exception;

class LoginBase
{
  /**
   * Decode the Apple encoded JWT using Apple's public key for the signing.
   *
   * @param string $identityToken
   * @return object
   */
  public  function decodeIdentityToken(string $identityToken): object
  {
    $publicKeyKid = JWT::getPublicKeyKid($identityToken);
    $publicKeyData = self::fetchPublicKey($publicKeyKid);
    $publicKey = $publicKeyData['publicKey'];
    $alg       = $publicKeyData['alg'];
    $payload = JWT::decode($identityToken, $publicKey, [$alg]);
    return $payload;
  }

  /**
   * Fetch Apple's public key from the auth/keys REST API to use to decode
   * the Sign In JWT.
   *
   * @param string $publicKeyKid
   * @return array
   */
  public function fetchPublicKey(string $publicKeyKid): array
  {
    $publicKeys        = file_get_contents('https://appleid.apple.com/auth/keys');
    $decodedPublicKeys = json_decode($publicKeys, true);

    if (!isset($decodedPublicKeys['keys']) || count($decodedPublicKeys['keys']) < 1) {
      throw new Exception('Invalid key format.');
    }

    $kids             = array_column($decodedPublicKeys['keys'], 'kid');
    $parsedKeyData    = $decodedPublicKeys['keys'][array_search($publicKeyKid, $kids)];
    $parsedPublicKey  = JWK::parseKey($parsedKeyData);
    $publicKeyDetails = openssl_pkey_get_details($parsedPublicKey);

    if (!isset($publicKeyDetails['key'])) {
      throw new Exception('Invalid public key details.');
    }

    return [
      'publicKey' => $publicKeyDetails['key'],
      'alg'       => $parsedKeyData['alg']
    ];
  }

}