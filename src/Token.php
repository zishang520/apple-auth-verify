<?php
namespace luoyy\AppleAuthVerify;

use GuzzleHttp\Client;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use luoyy\AppleAuthVerify\Exceptions\TokenException;
use Throwable;

class Token
{
    protected static $keys = null;

    protected static function getKeys(): array
    {
        if (!is_null(self::$keys)) {
            return self::$keys;
        }
        try {
            $data = (string) (new Client())->request('GET', 'https://appleid.apple.com/auth/keys', [
                'headers' => [
                    'pragma' => 'no-cache',
                    'cache-control' => 'no-cache',
                    'upgrade-insecure-requests' => '1',
                    'dnt' => '1',
                    'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.81 Safari/537.36',
                    'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                    'accept-encoding' => 'gzip, deflate',
                    'accept-language' => 'zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7'
                ]
            ])->getBody();
            if (!empty($data) && !empty($body = json_decode($data, true))) {
                if (isset($body['keys'])) {
                    return self::$keys = $body['keys'];
                }
            }
        } catch (Throwable $e) {
            throw new TokenException($e->getMessage(), $e->getCode(), $e->getPrevious());
        }
        throw new TokenException('Failed to get keys.');
    }

    public static function verify(string $identityToken)
    {
        try {
            // The serializer manager. We only use the JWS Compact Serialization Mode.
            $serializerManager = new JWSSerializerManager([
                new CompactSerializer()
            ]);
            // We try to load the token.
            $jws = $serializerManager->unserialize($identityToken);
            // We instantiate our JWS Verifier.
            $jwsVerifier = new JWSVerifier(new AlgorithmManager([new RS256()]));
            if ($jwsVerifier->verifyWithKeySet($jws, new JWKSet(array_map(fn($key) => new JWK($key), self::getKeys())), 0)) {
                return json_decode($jws->getPayload());
            }
            return false;
        } catch (TokenException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new TokenException($e->getMessage(), $e->getCode(), $e->getPrevious());
        }
    }
}
