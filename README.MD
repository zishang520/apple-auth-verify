# Apple login authorization information acquisition

### Installation package
```bash
composer require luoyy/apple-auth-verify
```

### Quick Sample Usage
```php
/**
 * DEMO
 */
use luoyy\AppleAuthVerify\Exceptions\TokenException;
use luoyy\AppleAuthVerify\Token;

try {
    if (($identity = Token::verify($request->get('identityToken'))) === false) {
        throw new AuthException('identityToken verification failed.', 400);
    }
} catch (TokenException $e) {
    throw new AuthException('identityToken Parsing failed.', 400);
}

if (time() > $identity->exp) {
    throw new AuthException('identityToken Expired, please re-authorize.', 400);
}
```
### Update log
* `2021.04.29`：Initialize the warehouse
