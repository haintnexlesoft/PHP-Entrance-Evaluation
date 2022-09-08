<?php


namespace Admin\Ex03\Auth;


use Firebase\JWT\JWT;
use Firebase\JWT\Key;
header("Content-Type: application/json");
class Auth
{


    public static function createJWT($payload)
    {

        $privateKey = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC8kGa1pSjbSYZVebtTRBLxBz5H4i2p/llLCrEeQhta5kaQu/Rn
vuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t0tyazyZ8JXw+KgXTxldMPEL9
5+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4ehde/zUxo6UvS7UrBQIDAQAB
AoGAb/MXV46XxCFRxNuB8LyAtmLDgi/xRnTAlMHjSACddwkyKem8//8eZtw9fzxz
bWZ/1/doQOuHBGYZU8aDzzj59FZ78dyzNFoF91hbvZKkg+6wGyd/LrGVEB+Xre0J
Nil0GReM2AHDNZUYRv+HYJPIOrB0CRczLQsgFJ8K6aAD6F0CQQDzbpjYdx10qgK1
cP59UHiHjPZYC0loEsk7s+hUmT3QHerAQJMZWC11Qrn2N+ybwwNblDKv+s5qgMQ5
5tNoQ9IfAkEAxkyffU6ythpg/H0Ixe1I2rd0GbF05biIzO/i77Det3n4YsJVlDck
ZkcvY3SK2iRIL4c9yY6hlIhs+K9wXTtGWwJBAO9Dskl48mO7woPR9uD22jDpNSwe
k90OMepTjzSvlhjbfuPN1IdhqvSJTDychRwn1kIJ7LQZgQ8fVz9OCFZ/6qMCQGOb
qaGwHmUK6xzpUbbacnYrIM6nLSkXgOAwv7XXCojvY614ILTK3iXiLBOxPu5Eu13k
eUz9sHyD6vkgZzjtxXECQAkp4Xerf5TGfQXGXhxIX52yH+N2LtujCdkQZjXAsGdm
B2zNzvrlgRmgBrklMTrMYgm1NPcW+bRLGcwgW2PTvNM=
-----END RSA PRIVATE KEY-----
EOD;
        return JWT::encode($payload, $privateKey, 'RS256');
    }

    public static function decodeJWT($jwt)
    {
        $publicKey = <<<EOD
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kGa1pSjbSYZVebtTRBLxBz5H
4i2p/llLCrEeQhta5kaQu/RnvuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t
0tyazyZ8JXw+KgXTxldMPEL95+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4
ehde/zUxo6UvS7UrBQIDAQAB
-----END PUBLIC KEY-----
EOD;

        return JWT::decode($jwt, new Key($publicKey, 'RS256'));
    }

    public static function connect_db()
    {
        $servername = "178.128.109.9";
        $username = "test01";
        $password = "PlsDoNotShareThePass123@";
        $dbname = "entrance_test";

        $conn = new \mysqli($servername, $username, $password, $dbname);

        if ($conn->connect_error) {
            http_response_code(500);
            return "Internal error";
        }
        return $conn;
    }

    static function getHashPassword($password, $options = [
        'cost' => 12,
    ]) {

        return password_hash($password, PASSWORD_BCRYPT, $options);
    }

    static function checkValidate($email, $password) {
        if ( strlen($password) < 8 || strlen($password) > 20) {
            http_response_code(400);
            return false;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            return false;
        }
        return  true;
    }

    public static function signIn()
    {


        $data = json_decode(file_get_contents("php://input"));
        if (!isset($data->email) || !isset($data->password)) {
            http_response_code(400);
            return false;
        }
        $email = htmlspecialchars($data->email); // "emailtest@gmail.com";
        $password = htmlspecialchars($data->password);// "12345678";

        if (!self::checkValidate($email, $password)) {
            http_response_code(400);
            return false;
        }

        $conn = self::connect_db();

        $sql = "SELECT id, first_name as firstName, last_name as lastName, concat(first_name, ' ', last_name) as displayName, email, password FROM users WHERE email='" . $email . "'";

        $result = $conn->query($sql);

        if (mysqli_num_rows($result) > 0) {

            $user = \mysqli_fetch_object($result);

            if (!password_verify($password, $user->password)) {
                http_response_code(400);
                return false;
            }

            unset($user->password);

            $payloadToken = array('sub' => $user->id, 'name' => $user->displayName, 'exp' => (time() + 3600));
            $payloadRefreshToken = array('sub' => $user->id, 'name' => $user->displayName, 'exp' => (time() + 30 * 24 * 3600));

            $token = self::createJWT($payloadToken);
            $refreshToken = self::createJWT($payloadRefreshToken);


            $sql = "INSERT INTO tokens (created_at, expires_in, refresh_token, updated_at, user_id) 
VALUES ('" . date('Y-m-d H:i:s') . "', '" . date('Y-m-d H:i:s', $payloadRefreshToken['exp']) . "', '" . $refreshToken . "','" . date('Y-m-d H:i:s') . "','" . $user->id . "')";

            $conn->query($sql);

            $responseObject = new \stdClass();
            $responseObject->user = $user;

            $responseObject->token = $token;
            $responseObject->refreshToken = $refreshToken;

            return json_encode($responseObject);

        }

        $conn->close();


        http_response_code(500);

    }

    public static function signUp()
    {

        $conn = self::connect_db();
        $data = json_decode(file_get_contents("php://input"));

        if (!isset($data->email) || !isset($data->password) || !isset($data->firstName)) {
            http_response_code(400);
            return false;
        }

        $email = htmlspecialchars($data->email); // "emailtest@gmail.com";
        $password = htmlspecialchars($data->password);// "12345678";
        $first_name = htmlspecialchars($data->firstName);
        $last_name = htmlspecialchars($data->lastName);

        if(!self::checkValidate($email, $password)) {
            http_response_code(400);
            return false;
        }

        $password = self::getHashPassword($password);

        $sql = "INSERT INTO users(first_name, last_name, email, password, created_at, updated_at) 
VALUES ('" . $first_name . "','" . $last_name . "','" . $email . "','" . $password . "','" . date('Y-m-d H:i:s') . "','" . date('Y-m-d H:i:s') . "')";
        $result = $conn->query($sql);

        $sql = "SELECT id, first_name as firstName, last_name as lastName, concat(first_name, ' ', last_name) as displayName, email FROM users WHERE email='".$email."'";
        $result = $conn->query($sql);
        $user = \mysqli_fetch_object($result);
        http_response_code(200);
        return json_encode($user);

        $conn->close();


        http_response_code(500);
    }

    public static function signOut() {
        $conn = self::connect_db();
        $authorization = '';
        if (isset($_SERVER['Authorization'])) {
            $authorization = ($_SERVER["Authorization"]);
        }else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $authorization = ($_SERVER["HTTP_AUTHORIZATION"]);
        }

        $bearerJwt = '';
        if (preg_match('/Bearer\s(\S+)/', $authorization, $matches)) {
            $bearerJwt = $matches[1];
        }

        try{
            $jwt = self::decodeJWT($bearerJwt);
        }catch (\Exception $e) {
            http_response_code(404);
            return false;
        }

        if(!isset($jwt->sub) || !isset($jwt->name)) {
            http_response_code(404);
            return false;
        }

        $userId = $jwt->sub;


        $sql = "SELECT created_at, expires_in, refresh_token, updated_at, user_id FROM tokens WHERE user_id='".$userId."' ORDER BY created_at DESC LIMIT 1";
        $result = $conn->query($sql);
        $tokens = \mysqli_fetch_object($result);

        if(!isset($tokens->user_id)) {
            http_response_code(500);
            return false;
        }

        $sql = "DELETE FROM tokens WHERE user_id='".$userId."'";
        $result = $conn->query($sql);

        if($result) {
            http_response_code(200);
            return false;
        }

        http_response_code(500);
    }

    public static function getRefreshToken() {
        $conn = self::connect_db();
        $authorization = '';
        if (isset($_SERVER['Authorization'])) {
            $authorization = ($_SERVER["Authorization"]);
        }else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $authorization = ($_SERVER["HTTP_AUTHORIZATION"]);
        }

        $bearerJwt = '';
        if (preg_match('/Bearer\s(\S+)/', $authorization, $matches)) {
            $bearerJwt = $matches[1];
        }

        $jwt = self::decodeJWT($bearerJwt);

        if(!isset($jwt->sub) || !isset($jwt->name)) {
            http_response_code(404);
            return false;
        }

        $userId = $jwt->sub;


        $sql = "SELECT created_at, expires_in, refresh_token, updated_at, user_id FROM tokens WHERE user_id='".$userId."' ORDER BY created_at DESC LIMIT 1";
        $result = $conn->query($sql);
        $tokens = \mysqli_fetch_object($result);

        if(!isset($tokens->user_id)) {
            http_response_code(404);
            return false;
        }
        $payloadToken = array('sub' => $tokens->user_id, 'name' => $jwt->name, 'exp' => (time() + 3600));
        $payloadRefreshToken = array('sub' => $tokens->user_id, 'name' => $jwt->name, 'exp' => (time() + 30 * 24 * 3600));

        $token = self::createJWT($payloadToken);
        $refreshToken = self::createJWT($payloadRefreshToken);

        try {
            $sql = "INSERT INTO tokens (created_at, expires_in, refresh_token, updated_at, user_id) 
VALUES ('" . date('Y-m-d H:i:s') . "', '" . date('Y-m-d H:i:s', $payloadRefreshToken['exp']) . "', '" . $refreshToken . "','" . date('Y-m-d H:i:s') . "','" . $tokens->user_id . "')";

            $conn->query($sql);

            $responseObject = new \stdClass();
            $responseObject->token = $token;
            $responseObject->refreshToken = $refreshToken;
            http_response_code(200);
            return json_encode($responseObject);
        }catch (\Exception $e) {
            http_response_code(500);
        }

    }
}
