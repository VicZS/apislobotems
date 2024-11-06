<?php
    use Psr\Http\Message\ResponseInterface as Response;
    use Psr\Http\Message\ServerRequestInterface as Request;
    use Slim\Factory\AppFactory;
    use \Firebase\JWT\JWT;
    
    require __DIR__ . '/api/vendor/autoload.php';
    use MyFirebase\Firebase as Fb;
    require_once 'MyFirebase.php';

    $project = 'loboteams-47dc1-default-rtdb';
    $firebase = new Fb($project);

    $app = AppFactory::create();
    $app->setBasePath("/api");


    $app->get('/', function($request, $response, $args){
        $response->write("Apis Loboteams");
        return $response;
    });

    //--------------------Configuracion Token----------------------//

    function GenerarToken($email, $pass){

        $key = "123456";

        // Configuración del encabezado del token
        $header = [
            "typ" => "JWT",
            "alg" => "HS256"
        ];

        //tiempo de validez en minutos
        $tiempoValidez = 1;
        $expiration_time = time() + (120 * $tiempoValidez);

        // Información del payload (puede ser cualquier dato que desees incluir)
        $payload = [
            "email" => $email,
            "pass" => $pass,
            "exp" => $expiration_time
        ];

        // Genera el token JWT
        $token = JWT::encode($payload, $key, 'HS256');

        return $token;
    };
    

    //-------Funciones-------

    //Autenticacion

    function Autenticar($user, $pass) {

        global $firebase;
       // $categoria = strtolower("usuarios");

        if($user == ''){
            $resp = array(
                'code' =>500,
                'message' =>$firebase->obtainMessage(500),
                "status" => "error"
            );
            
            return $resp;
        }

        if($pass == ''){
            $resp = array(
                'code' => 501,
                'message' => $firebase->obtainMessage(501),
                "status" => "error"
            );
            
            return $resp;
        }

        if($firebase->isUserInDB($user)){
            if ($firebase->obtainPassword($user) == md5($pass)){
                $data = $firebase->obtainDetalles($user);

                // Obtener el valor del atributo "email"
                $email = $data->email;

                // Obtener el valor del atributo "pass"
                $pass = $data->pass;

                $token = GenerarToken($email,$pass);
                
                $resp = array(
                    "code" => 206,
                    "message" => $firebase->obtainMessage(206),
                    "status" => "OK",
                    "token" => $token
                );
                
                return $resp;


            }else{
                $resp = array(
                    'code' => 501,
                    'message' => $firebase->obtainMessage(501),
                    'status' => 'error'
                    );
                    
                    return $resp;
            }
        }else{
            
            $resp = array(
                'code' =>500,
                'message' =>$firebase->obtainMessage(500),
                'status' => 'error'
                );
            
            return $resp;
        }
    };


    $app->post('/autenticacionPost', function($request, $response, $args){

        global $firebase;
    
        $reqPost = $request->getParsedBody();
        $user = $reqPost['user'] ?? null;
        $pass = $reqPost['pass'] ?? null;
    
        // Si los datos no están en el cuerpo de la solicitud, intenta leerlos de los encabezados
        if ($user === null || $pass === null) {
            $user = $request->getHeader('user')[0] ?? null;
            $pass = $request->getHeader('pass')[0] ?? null;
        }
    
        // Si aún no se han proporcionado datos de usuario y contraseña, devuelve un error
        if ($user === null || $pass === null) {
            $response->write(json_encode(["error" => "Datos de usuario y / o contraseña no proporcionados"], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            return $response->withStatus(400);
        }
    
        // Procede con la autenticación utilizando los datos obtenidos
        $RespuestaT1 = Autenticar($user, $pass);
    
        // Devuelve la respuesta de autenticación
        $response->write(json_encode($RespuestaT1, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        return $response;
    });
    
    $app->get('/consulta', function($request, $response, $args){
        $response->write("Apis Loboteams consulta");
        return $response;
    });


    $app->run();

    //<!--variables de sesion-->
?>

